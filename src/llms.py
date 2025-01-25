from flask import flash
from . import config
from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum
from .models import Repo, Post, Settings, get_default_daily_summary_prompt
import json
from groq import Groq
from openai import OpenAI
from anthropic import Anthropic
import instructor
import os
import logging
import requests


class Summary(BaseModel):
    summary: str = Field(description="This is a summary analysis of the commit patches")
    programming_language_used: Optional[str] = Field(description="The programming language used in the commit patches in case it is easily identifiable", default=None)


def gpt_generate_summary_for_user_commits(repo_description: str, commit_patches_data: str) -> (str, str):

    provider = "groq"
    model = ""
    if provider == "groq":
        client = instructor.from_groq(Groq(api_key=config.get('GROQ_API_KEY')))
        model = config.get('NEWEST_LLAMA_MODEL')
        content, language = get_post_summary(client, repo_description, commit_patches_data, model)
        return content, language, model

    elif provider == "server":
        logging.info("making summary with server")
        from textwrap import dedent
        url = "http://173.212.244.238:8000/summary"
        headers = {
            "Content-Type": "application/json",
            "api-key": config.get("LLM_SERVER_API_KEY")
        }

        system_message = dedent(f"""\
            Your task is to summarize the following commit patches into a concise, easily readable message that describes the functional changes made. Do not just state what files were changed or added, but explain the changes in terms of their functionality and impact. For instance, if an algorithm was implemented, describe which algorithm it is and what problem it solves. If there are no patches or data to summaries just say 'no changes'. The summary should be brief, like a Tweet (max 280 characters). 

            For context, here is the repo owner's description of the whole repo:
            {repo_description}

            Here are the commit patches:
            {commit_patches_data}""")

        messages = [
            {
                "role": "system",
                "content": system_message
            },
            {
                "role": "user",
                "content": "Please generate a brief summary of these commit patches, focusing on the functionality of the changes."
            }
        ]

        payload = {
            "messages": messages
        }
        try:
            logging.info("Final payload: ")
            logging.info(json.dumps(payload, indent=2, ensure_ascii=False))
            response = requests.post(url, headers=headers, json=payload)
            logging.info("Raw Response:", response.text)  # Add this line
            response.raise_for_status()  
            
            result = response.json()
            summary = result.get("summary")
            programming_language = result.get("programming_language_used")
            return summary, programming_language, "server-model"
            
        except (requests.exceptions.HTTPError, ValueError) as err:
            logging.error(f"LLM Server error: {err}")
            create_admin_notification(f"LLM Server error: {err}")
            
            client = instructor.from_openai(
                OpenAI(
                    base_url="https://openrouter.ai/api/v1", 
                    api_key=config.get('OPENROUTER_API_KEY'),
                ),
                mode=instructor.Mode.JSON,
            )
            model = config.get('OPENROUTER_MODEL')
            content, language = get_post_summary(client, repo_description, commit_patches_data, model)
            return content, language, model
            

    elif provider == "local":
        client = instructor.from_openai(OpenAI(base_url="http://localhost:11434/v1",api_key="ollama"),mode=instructor.Mode.JSON)
        model = config.get('LOCAL_LLAMA_MODEL')
        content, language = get_post_summary(client, repo_description, commit_patches_data, model)
        return content, language, model

    elif provider == "openrouter":
        client = instructor.from_openai(
            OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=config.get('OPENROUTER_API_KEY'),
                ),
            mode=instructor.Mode.JSON,
        )
        model = config.get('OPENROUTER_MODEL')
        content, language = get_post_summary(client, repo_description, commit_patches_data, model)
        return content, language, model

    else:
        create_admin_notification(f"Invalid provider: {provider}")
        raise ValueError(f"Invalid provider: {provider}")


def get_post_summary(client, repo_description, commit_patches_data, model):
    resp = client.chat.completions.create(
        model=model,
        max_tokens=1024,
        messages=[
                {
                "role": "system", "content": f"""Your task is to summarize the following commit patches into a concise, easily readable message that describes the functional changes made. Do not just state what files were changed or added, but explain the changes in terms of their functionality and impact. For instance, if an algorithm was implemented, describe which algorithm it is and what problem it solves. If there are no patches or data to summaries just say 'no changes'. The summary should be brief, like a Tweet (max 280 characters). 

    For context, here is the repo owner's description of the whole repo:
    
    {repo_description}

    Here are the commit patches:

    {commit_patches_data}"""
                },
                {
                    "role": "user","content": f"Please generate a brief summary of these commit patches, focusing on the functionality of the changes."
                },
        ],
        response_model=Summary,
    )
    logging.info(f"response: {resp.summary}")
    return resp.summary, resp.programming_language_used


class FileAnalysisCategory(str, Enum):
    """ enum for file analysis decision """
    full = "full"
    beginning = "beginning"
    never = "never"

class FileAnalysis(BaseModel):
    decision: FileAnalysisCategory = Field(description="The decision on how to analyze the file")

def analyze_first_25_lines_of_code(filename: str, code: str):
    """ Uses GPT to analyze first 50 lines to determine if the filetype
    should be marked as analyze_full, analyze_never(eg. binary files) or analyze_beginning(eg. certain data files to get the idea of the change) 
    """
    client = instructor.from_openai(
            OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=config.get('OPENROUTER_API_KEY'),
                ),
            mode=instructor.Mode.JSON,
        )
    model = config.get('OPENROUTER_MODEL')

    resp = client.chat.completions.create(
        model=model,
        max_tokens=1024,
        messages=[
            {
              "role": "system",
              "content": "Analyze the provided filename and the first 25 lines of its content to determine the appropriate level of analysis for files with this extension. Make your decision based on the content's potential importance, the predictability of the file's content from its name, and its readability. Output should be one of the following decisions: \"full\", \"beginning\", \"never\".\n\nInput:\n\n    Filename: example.extension\n    Content:\n\n[First 25 lines of the file]\n\nOutput Decision Criteria:\n\n    \"full\": The file's content is crucial for understanding changes, and missing details could lead to overlooking important information. Applicable to source code, significant configuration changes, etc.\n    \"beginning\": The file's format is repetitive, and understanding the first 10 lines provides sufficient context. Suitable for large data files with a consistent format.\n    \"never\": The file's content is predictable from its name, non-human-readable, or generally contains no relevant information for analysis (e.g., binary, media files).\n\nOutput:\n\n    [The one word decision here]\n"
            },
            {
              "role": "user",
              "content": "\n    Filename: update_log.md\n    Content:\n\n# Update Log\n- Fixed issue #224\n- Improved performance of data processing module\n...\n\n"
            },
            {
              "role": "assistant",
              "content": "full"
            },
            {
              "role": "user",
              "content": "\n    Filename: data_2023.csv\n    First 50 Lines:\n\nid,name,value\n1,Item A,100\n2,Item B,150\n3,Item C,200\n...\n"
            },
            {
              "role": "assistant",
              "content": "beginning"
            },
            {
              "role": "user",
              "content": "    Filename: company_logo.png\n    Content:\n\n�PNG\n..."
            },
            {
              "role": "assistant",
              "content": "never"
            },
            {
              "role": "user",
              "content": "\n    Filename: database_migration.sql\n    Content:\n\n-- Migration: Add new column to users table\nALTER TABLE users ADD COLUMN last_login TIMESTAMP;\n-- Add index for the new column\nCREATE INDEX idx_users_last_login ON users(last_login);"
            },
            {
              "role": "assistant",
              "content": "full"
            }, 
            {
                "role": "user",
                "content": f"    Filename: {filename}\n    Content:\n\n{code}"
            }
          ],
        response_model=FileAnalysis,
    )

    return resp.decision, 2


class CommitSignifiganceCategory(str, Enum):
    """ enum for commit analysis decision """
    significant = "significant"
    not_significant = "not significant"

class CommitAnalysis(BaseModel):
    decision: CommitSignifiganceCategory = Field(description="The decision on the commit analysis")


def gpt_judge(commit_patches_data: str):

    provider = "openrouter"
    model = ""
    if provider == "groq":
        logging.info("Using groq model")
        client = instructor.from_groq(Groq(api_key=config.get('GROQ_API_KEY')))
        model = config.get('NEWEST_LLAMA_MODEL')
        logging.info(f"starting judge with model: {model}")
        return get_judge_decision(client, commit_patches_data, model)

    elif provider == "local":
        logging.info("Using local model")
        client = instructor.from_openai(OpenAI(base_url="http://localhost:11434/v1",api_key="ollama"),mode=instructor.Mode.JSON)
        model = config.get('LOCAL_LLAMA_MODEL')
        logging.info(f"starting judge with model: {model}")
        return get_judge_decision(client, commit_patches_data, model)

    elif provider == "openrouter":
        client = instructor.from_openai(
            OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=config.get('OPENROUTER_API_KEY'),
                ),
            mode=instructor.Mode.JSON,
        )
        model = config.get('OPENROUTER_MODEL')
        return get_judge_decision(client, commit_patches_data, model)

    else:
        create_admin_notification(f"Invalid provider: {provider}")
        raise ValueError(f"Invalid provider: {provider}")


def get_judge_decision(client, commit_patches_data, model):

    logging.info(f"starting judge with model: {model}")
    messages = [
                    {"role": "system", "content": f"""Your task is to analyze the provided commits and evaluate their significance. If there are multiple commits, analyze them collectively. Your response should indicate whether these commits are 'significant' or 'not significant'.

                A 'significant' commit could:
                - Add a new feature or substantially progress a larger feature
                - Perform a major refactor or significant code cleanup
                - Resolve a critical bug or issue that has a major impact on the system or user experience

                A 'not significant' commit could:
                - Involve minor tweaks or bug fixes that don't have a major impact
                - Add comments or documentation
                - Perform small refactoring tasks
                - Add a file or files without significant changes

                Special Consideration:
                - Sometimes a change may look small but can have a significant impact, such as fixing a critical bug that has been causing stress in the product. These should also be considered 'significant'.

                Please judge the following commit patches and determine their significance by outputing ONLY 'significant' or 'not significant'.:

                {commit_patches_data}"""},
                    {"role": "user","content": f"Please evaluate if the given commit patches are 'significant' or 'not significant'."},
                ]
    logging.info(messages)
    resp = client.chat.completions.create(
        model=model,
        max_tokens=1024,
        response_model=CommitAnalysis,
        messages=messages,
    )
    logging.info(f"response: {resp.decision}")
    return resp.decision
        
