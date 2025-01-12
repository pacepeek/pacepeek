from random import choice
from sqlalchemy.sql.functions import current_time
from sqlalchemy.orm import aliased
import json
from . import db,config
from pprint import pprint
from zoneinfo import ZoneInfo
import os
import logging, humanize

from .models import User, Repo, Post, UserRepoLastSeen, Commit, Branch,Notification, Filetype, Settings
from .llms import analyze_first_25_lines_of_code

import base64


import time
import requests
from flask import session, flash, redirect, url_for, current_app, abort, request
from flask_login import current_user
from datetime import datetime
import hashlib
import hmac


class GPTCreateSummaryError(Exception):
    pass

class GPTFileAnalysisError(Exception):
    pass

class GPTJudgeError(Exception):
    pass

def get_top_three_languages_for_user(user: User):
    """ returns the top three languages for a user with a query """
    """ uses the Post.programming_language column """
    top_three_languages = db.session.query(Post.programming_language, db.func.count(Post.programming_language).label('count')).filter(Post.author_github_id == user.github_id, Post.programming_language != None).group_by(Post.programming_language).order_by(db.desc('count')).limit(3).all()
    return top_three_languages


def get_active_models_from_groq() -> list:
    url = "https://api.groq.com/openai/v1/models"
    api_key = config.get("GROQ_API_KEY")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    print(response.json())
    return response.json()['models']

def deactivate_user_webhooks(user: User):
    """ deactivates webhooks for user's repos """
    from .github_utils import deactivate_webhook_for_user_repo_with_installation_token
    logging.info(f"deactivating webhooks for user {user.github_login}")
    for repo in Repo.query.filter_by(owner_github_id=user.github_id).all():
        if repo.webhook_id:
            if deactivate_webhook_for_user_repo_with_installation_token(repo):
                logging.info(f"Deactivated webhook for repo {repo.name}")
            else:
                logging.info(f"Could not deactivate webhook for repo {repo.name} since it probably was already deactivated")
        repo.webhook_active = False
    db.session.commit()
    logging.info(f"deactivated webhooks for user {user.github_login}")

def remove_premium_from_user(user: User):
    """ removes premium from user and deactivates webhooks for their repos """
    from .github_utils import deactivate_webhook_for_user_repo_with_installation_token
    user.is_premium = False
    logging.info(f"removing premium from user {user.github_login}")
    deactivate_user_webhooks(user)
    db.session.commit()
    logging.info(f"removed premium from user {user.github_login}")

def reactivate_user_webhooks(user: User):
    """ reactivates webhooks for user's repos """
    from .github_utils import reactivate_webhook_for_user_repo_with_installation_token
    logging.info(f"reactivating webhooks for user {user.github_login}")
    for repo in Repo.query.filter_by(owner_github_id=user.github_id).all():
        if repo.webhook_id:
            if reactivate_webhook_for_user_repo_with_installation_token(repo):
                logging.info(f"Deactivated webhook for repo {repo.name}")
            else:
                logging.info(f"Could not deactivate webhook for repo {repo.name} since it probably was already deactivated")
        repo.webhook_active = True
    db.session.commit()
    logging.info(f"reactivated webhooks for user {user.github_login}")

def give_premium_to_user(user: User):
    """ gives premium to user and reactivates webhooks for their repos """
    from .github_utils import reactivate_webhook_for_user_repo_with_installation_token
    user.is_premium = True
    logging.info(f"giving premium to user {user.github_login}")
    reactivate_user_webhooks(user)
    db.session.commit()
    logging.info(f"gave premium to user {user.github_login}")


def verify_signature(payload_body, secret_token, signature_header):
    if not signature_header:
        abort(403, description="X-Hub-Signature-256 header is missing!")
    hash_object = hmac.new(secret_token, msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        abort(403, description="Request signatures didn't match!")

def log_the_push_context(context: str):
    if not current_app.debug:
        with open(os.path.join(config.get('LOG_FOLDER_PATH'),'pacepeek_info.log'), 'r') as f:
            lines = f.readlines()
            recent_lines = lines[-1000:]
        current_timestamp = int(time.time())
        log_filename = f'pacepeek_push_context_{current_timestamp}.log'
        context_filename = os.path.join(config.get('LOG_FOLDER_PATH'),log_filename)
        with open(os.path.join(config.get('LOG_FOLDER_PATH'),context_filename), 'w') as f:
            f.writelines(recent_lines)
            f.write(f"Push context: {context}\n")
        create_admin_notification(f"Push context: {context} has been logged to {context_filename}\n")


def log_the_error_context(e: Exception, line_count: int = 200,  context: str = ""):
    if not current_app.debug:
        with open(os.path.join(config.get('LOG_FOLDER_PATH'),'pacepeek_info.log'), 'r') as f:
            lines = f.readlines()
            recent_lines = lines[-line_count:]
        logging.exception(f"Error with context: {context} happened.")
        with open(os.path.join(config.get('LOG_FOLDER_PATH'),'pacepeek_error.log'), 'r') as f:
            error_lines = f.readlines()
        # Find the latest trace log
        latest_trace_line_number = None
        for line in reversed(error_lines):
            if 'Traceback' in line:
                latest_trace_line_number = error_lines.index(line)
                break

        if latest_trace_line_number is None:
            print("No trace log found in the error log.")
            recent_traceback_lines = []
        else:
            recent_traceback_lines = error_lines[-latest_trace_line_number:]

        current_timestamp = int(time.time())
        log_filename = f'pacepeek_context_{current_timestamp}.log'
        context_filename = os.path.join(config.get('LOG_FOLDER_PATH'),log_filename)
        with open(os.path.join(config.get('LOG_FOLDER_PATH'),context_filename), 'w') as f:
            f.writelines(recent_lines)
            f.writelines(recent_traceback_lines)
            f.write(f"Error context: {context}\n")
            f.write(f"Error: {e}\n")
        create_admin_notification(f"Error: {e} with context: {context}  and traceback: {recent_traceback_lines[:5]} has been logged to {context_filename}\n")

def send_user_email(user: User, topic: str, message: str):
  	return requests.post(
  		"https://api.mailgun.net/v3/sandbox06acda4d8b5546ad89902875a26f604e.mailgun.org/messages",
  		auth=("api", config.get("MAILGUN_API_KEY")),
  		data={"from": f"Excited User <mailgun@sandbox06acda4d8b5546ad89902875a26f604e.mailgun.org>",
  			"to": ["rasmus@ahtava.com", "YOU@sandbox06acda4d8b5546ad89902875a26f604e.mailgun.org"],
  			"subject": topic,
  			"text": message})

def create_report(message: str):
    if not current_user.is_authenticated:
        logging.error(f"User is not authenticated when trying to create a report")
        return
    report = Notification(message=message,user=current_user, category='report', creation_timestamp=int(time.time()))
    db.session.add(report)
    db.session.commit()
    logging.info(f"created report: {report.message}")

def create_admin_notification(message: str):
    """ creates a notification for all admins """
    noti = Notification(message=message, category='admin', creation_timestamp=int(time.time()))
    db.session.add(noti)
    db.session.commit()
    logging.info(f"created admin notification: {noti.message}")

def create_user_notification(user: User, message: str, link: str = ""):
    """ creates a notification for a user """
    noti = Notification(message=message, category='user', user_id=user.id, creation_timestamp=int(time.time()))
    if link:
        noti.link = link
    db.session.add(noti)
    db.session.commit()
    logging.info(f"created user notification: {noti.message}")

def move_col_to_left_from_left(p_col: int, free_row: int, grid: list[list], pos: dict, parents_indicies: list[int]):
    """ free_row: int, idx of the commit row from on up we insert empty col to the left and update commits there on pos map """
    """ under it we add a empty col to the end of the every row down so it balances the grid """
    insert_col = p_col+1
    logging.info(f"inserting empty col to left with insert_col: {insert_col} and up from free_row: {free_row}")
    have_corrected_parents = False
    for i in range(free_row,len(grid)):
        row = grid[i]
        logging.info(f"current row: {row}")
        if i % 2 == 1: # if connect row
            logging.info("row is connect row")
            row.insert(insert_col,[])
        else: # commit row
            logging.info("row is commit row")
            row.insert(insert_col,None)
        logging.info("moi")
        if i % 2 == 1 and (('from-left' in row[insert_col-1] or 'to-left' in row[insert_col-1] or 'horizontal' in row[insert_col-1]) or (insert_col+1 < len(row) and ('from-right' in row[insert_col+1] or 'to-right' in row[insert_col+1] or 'horizontal' in row[insert_col+1]))):
            logging.info(f"adding horizontal to the empty connect row col: {row[insert_col+1]}, {row[insert_col]}, {row[insert_col-1]}")
            row[insert_col].append('horizontal')
        elif i % 2 == 0:
            # correct the row's commit in the pos map
            logging.info(f"correcting row: {row}s pos map")
            for i in range(insert_col,len(row)):
                if isinstance(row[i],Commit):
                    pos[row[i].sha]['col'] += 1
                if i in parents_indicies and not have_corrected_parents:
                    parents_indicies.remove(i)
                    parents_indicies.append(i+1)
                    have_corrected_parents = True
    logging.info(f"balancing the grid by adding empty col to the end of every row up to free_row: {free_row}")
    for i in range(0,free_row):
        if i % 2 == 0:
            grid[i].append(None)
        else:
            grid[i].append([])

    logging.info(f"leaving move_col_to_left_from_left")

def make_sure_top_col_is_empty_for_fav_child_connection(p_col: int, p_row: int, grid: list[list], pos: dict, parents_indicies: list[int]):
    logging.info(f"moving col to left from top if need. p_col: {p_col}, p_row: {p_row}, len(grid): {len(grid)}")
    idx_from_not_free_top = -1
    if p_col >= len(grid[-1]):
        logging.info(f"adding a column to the most left since out of bounds")
        for j in range(len(grid)):
            if j % 2 == 0:
                grid[j].append(None)
            else:
                grid[j].append([])

    for i in range(p_row+2,len(grid),2):
        logging.info(f"checking commit_row {i} len(grid[i])={len(grid[i])}: {grid[i]}")
        if grid[i][p_col]: # if commit or "line-through"
            logging.info(f"top col is not free so we need to make room for it on the left. (found commit): {grid[i][p_col]}")
            idx_from_not_free_top = i-1
            break
        logging.info(f"moi")
    logging.info(f"idx_from_not_free_top: {idx_from_not_free_top}")
    if idx_from_not_free_top != -1:
        logging.info(f"checking if left column is free and adding an empty column to the left if not")
        logging.info(f"p_col+1: {p_col+1}, len(grid[-1]): {len(grid[-1])}")
        if p_col+1 >= len(grid[-1]):
            logging.info(f"adding a column to the most left since out of bounds")
            for j in range(len(grid)):
                if j % 2 == 0:
                    grid[j].append(None)
                else:
                    grid[j].append([])
        else:
            logging.info(f"checking if the left column is free")
            left_col_free = True
            for i in range(p_row,len(grid),2):
                if grid[i][p_col+1]: # if commit or "line-through"
                    logging.info(f"row: {i}, col: {p_col+1} is not free: {grid[i][p_col+1]}")
                    left_col_free = False
                    break
            if not left_col_free:
                free_row_idx = -1
                logging.info(f"searching for free row where we can move stuff to the left by going down from row: {p_row}")
                for i in range(p_row,-1,-2):
                    free_row = True
                    logging.info(f"checking commit_row {i}: {grid[i]}")
                    for j in range(p_col+1,len(grid[i])):
                        if grid[i][j]: # if commit or "line-through"
                            logging.info(f"col {j} is not free: {grid[i][j]}")
                            free_row = False
                            break
                    if free_row:
                        free_row_idx = i
                        break
                if free_row_idx == -1:
                    free_row = 0
                    logging.info(f"free row stayed at -1 so we set it to 0")
                logging.info(f"free_row_idx rn before moving : {free_row_idx}")
                move_col_to_left_from_left(p_col,free_row_idx,grid,pos, parents_indicies)
            else:
                logging.info(f"left column is free already:)")


        
        # now left column should be free for us moving the top column to left
        logging.info(f"left column should be free now")

        logging.info(f"moving top column to left starting from row: {idx_from_not_free_top}")
        # idx_from_not_free_top is connect_row 
        have_corrected_parents = False
        for i in range(idx_from_not_free_top,len(grid)):
            row = grid[i]
            logging.info(f"current row({i}): {row}")
            if i % 2 == 1: # if connect row
                row[p_col+1] = row[p_col]
                if 'horizontal' in row[p_col] or 'from-right' in row[p_col] or 'to-right' in row[p_col]:
                    logging.info(f"adding only existing horizontal to row: {i}")
                    row[p_col] = ['horizontal']
                else:
                    row[p_col] = []
            else: # commit row
                row[p_col+1] = row[p_col]
                if isinstance(row[p_col],Commit):
                    pos[row[p_col].sha]['col'] += 1
                    logging.info(f"correcting pos map for commit {row[p_col]} from col {p_col} to {p_col+1} while len(row)={len(row)}")
                if p_col in parents_indicies and not have_corrected_parents:
                    logging.info(f"correcting parents_indicies since we moved the top column to left")
                    parents_indicies.remove(p_col)
                    parents_indicies.append(p_col+1)
                    have_corrected_parents = True
            logging.info(f"row after moving: {row}")
    else:
        logging.info(f"top col is free so we don't need to move anything")

    # now the top column should be free finally
    logging.info(f"top column should be free now")

def actually_add_childs_connections(commit: Commit, parent: Commit, grid: list[list], pos: dict, parents_indicies: list[int]):
    """ adds the childs connections to the parent and returns the col of the child """
    """ if commit has many parents the last connect_row is only made for the last parent"""
    """ also updates the pos map whenever it needs to """

    logging.info(f"IN ADD_CHILD,starting to add child {commit} to commit tree with parent: {parent.sha}")
    logging.info(f"IN ADD_CHILD,current parent({parent})'s fav children: {pos[parent.sha]['fav_children_lol']}")
    logging.info(f"IN ADD_CHILD,current parents row: {pos[parent.sha]['row']}")
    p_col = pos[parent.sha]['col']
    p_row = pos[parent.sha]['row']
    childs = pos[parent.sha]['children_so_far']

    # following if else is for making sure the cols which we are inserting connections are empty
    if commit.sha in pos[parent.sha]['fav_children_lol'] and not pos[parent.sha]['above_used'] and \
            len(pos[parent.sha]['fav_children_lol']) == 1:
        logging.info(f"IN ADD_CHILD,let's make sure above col is empty in if")
        # even tho this commit's above is unused but there can still be other commit/commit lines ahead it
        # so we need to check for that and make more room if needed
        make_sure_top_col_is_empty_for_fav_child_connection(p_col,p_row,grid,pos,parents_indicies)
        pos[parent.sha]['fav_children_lol'].remove(commit.sha)
        child_return_pos = 'top'
    else:
        logging.info(f"IN ADD_CHILD,let's make sure left col is empty in else. p_col: {p_col}, p_row: {p_row}, len(grid): {len(grid)} ")
        # if we are going to add child to left we need to make room for it here if needed
            
        if p_col+1 >= len(grid[-1]):
            logging.info(f"IN ADD_CHILD,adding a column to the most left")
            for j in range(len(grid)):
                if j % 2 == 0:
                    grid[j].append(None)
                else:
                    grid[j].append([])
        else:
            logging.info(f"IN ADD_CHILD,checking if the left column is free")
            left_col_free = True
            for i in range(p_row,len(grid),2):
                if grid[i][p_col+1]: # if commit or "line-through"
                    logging.info(f"IN ADD_CHILD,row: {i}, col: {p_col+1} is not free: {grid[i][p_col+1]}")
                    left_col_free = False
                    break
            if not left_col_free:
                free_row_idx = -1
                logging.info(f"IN ADD_CHILD,searching for free row where we can move stuff to the left by going down from row: {p_row}")
                for i in range(p_row,-1,-2):
                    free_row = True
                    logging.info(f"IN ADD_CHILD,checking commit_row {i}: {grid[i]}")
                    for j in range(p_col+1,len(grid[i])):
                        if grid[i][j]: # if commit or "line-through"
                            logging.info(f"IN ADD_CHILD,col {j} is not free: {grid[i][j]}")
                            free_row = False
                            break
                    if free_row:
                        free_row_idx = i
                        break
                if free_row_idx == -1:
                    logging.info(f"IN ADD_CHILD,free_row_idx stayed at -1 so we set it to 0")
                    free_row_idx = 0
                logging.info(f"IN ADD_CHILD,free_row_idx rn before moving : {free_row_idx}")
                move_col_to_left_from_left(p_col,free_row_idx,grid,pos,parents_indicies)
            else:
                logging.info(f"IN ADD_CHILD,left column is free already:)")
        # now left column should be free for us adding the child to left
        logging.info(f"IN ADD_CHILD,left column should be free now")
        child_return_pos = 'left'

    if pos[parent.sha]['row'] == len(grid)-1:
        logging.info("parent is currently on the last row of the grid so we need to add a connect row")

        # add the next connect row
        connect_row = []
        for i in range(len(grid[-1])):
            if i == p_col and child_return_pos == 'top':
                connect_row.append(['through'])
                pos[parent.sha]['above_used'] = True
                continue
            if i == p_col+1 and child_return_pos == 'left':
                connect_row.append(['from-right'])
                connect_row[p_col].append('to-left')
                if commit.sha in pos[parent.sha]['fav_children_lol']:
                    pos[parent.sha]['fav_children_lol'].remove(commit.sha)
                continue
            # we add the "trough"s here because commit can be merge and 
            # have multiple parents which have put their connections 
            # to this point so we are nice and append them haha.
            if isinstance(grid[-1][i],str):
                connect_row.append(['through'])
            else:
                connect_row.append([])

        grid.append(connect_row)
        logging.info(f"added connect row: {connect_row}")

    else:
        logging.info("parent is not on the last row. so we just add connections")
        if child_return_pos == 'top':
            pos[parent.sha]['above_used'] = True
            # we have made sure above col is empty in earlier code in this function
            logging.info(f"let's add through line to the top column")
            logging.info(f"grid[p_row+1][p_col]: {grid[p_row+1][p_col]}")
            for i in range(p_row+1,len(grid)):
                logging.info(f"i: {i}")
                logging.info(f"grid[i][p_col]: {grid[i][p_col]}")
                if i % 2 == 0: # if commit row
                    grid[i][p_col] = 'line-through'
                else:
                    if grid[i][p_col]:
                        grid[i][p_col].append('through')
                    else:
                        grid[i][p_col] = ['through']

            logging.info(f"added through line to the top column")
            # we don't need to remove this child from fav_children_lol since it doesn't matter anymore

        else: # add child to left
            logging.info(f"let's add child to left")

            logging.info(f"let's add to-left to the parent column")
            grid[p_row+1][p_col].append('to-left')
            #if childs > 1 or (childs == 1 and not pos[parent.sha]['above_used']):
            # we could add horizontal to the top left here but that has been done when moving possible left to left already
            logging.info(f"let's add from-right to the left column")
            if p_col+1 >= len(grid[-1]):
                logging.info(f"adding a column to the most left since out of bounds")
                for j in range(len(grid)):
                    if j % 2 == 0:
                        grid[j].append(None)
                    else:
                        grid[j].append([])
            if grid[p_row+1][p_col+1]:
                grid[p_row+1][p_col+1].append('from-right')
            else:
                grid[p_row+1][p_col+1] = ['from-right']

            logging.info(f"let's connect the left column to the top")
            for i in range(p_row+2,len(grid)):
                if i % 2 == 0: # if commit row
                    grid[i][p_col+1] = 'line-through'
                else:
                    if grid[i][p_col+1]:
                        grid[i][p_col+1].append('through')
                    else:
                        grid[i][p_col+1] = ['through']
            # removing this child from fav_children_lol if it's there
            # since we want the lastest fav child to be on the top column
            # and we are checking that by when fav_children_lol has only one child left
            if commit.sha in pos[parent.sha]['fav_children_lol']:
                pos[parent.sha]['fav_children_lol'].remove(commit.sha)
            

    pos[parent.sha]['children_so_far'] += 1

    logging.info(f"leaving add_child with child_return_pos: {child_return_pos}")
    if child_return_pos == 'left':
        return p_col+1
    else:
        return p_col


def add_childs_connection_to_parent(commit: Commit, parent: Commit, grid: list[list], pos: dict, parents_indicies: list[int] = []):
    # fav_children_lol is a list of shas of children commits which we want to be on the top column
    logging.info("starting add_childs_connection_to_parent")
    logging.info(f"pos: {pos}")
    if not pos[parent.sha]['fav_children_lol']:
        logging.info(f"fav children lol doesn't exist yet")
        most_fav_children = []
        second_most_fav_children_but_still_loved_tho = []
        somehow_still_hanging_on_children = []
        dev_or_main_child = None
        for child in parent.children:
            logging.info("moi")
            logging.info(f"pos[parent.sha]['col']: {pos[parent.sha]['col']}")
            if child.branch.name == parent.branch.name \
                    and child.previous_branch_name == parent.previous_branch_name:
                logging.info(f"child is on the same branch as parent and previous branch as parent")
                most_fav_children.append(child.sha)
            elif child.branch.name == parent.branch.name:
                logging.info(f"child is on the same branch as parent")
                second_most_fav_children_but_still_loved_tho.append(child.sha)
            # if child is on dev branch and parent is on main branch
            # just leave it there
            elif child.branch.name == child.repo.main_branch_name:
                logging.info(f"child is on main branch")
                somehow_still_hanging_on_children.append(child.sha)
            # if child is on dev branch and parent is on main branch
            # we need to make sure that the child is on the dev branch(which is on the left side right now exceptionally)
            # so we don't add it to the fav_children_lol so it goes to the side
            elif child.branch.name == child.repo.dev_branch_name and pos[parent.sha]['col'] > 0:
                logging.info(f"child is on dev branch and parent is on main branch")
                somehow_still_hanging_on_children.append(child.sha)
        if most_fav_children:
            logging.info(f"most_fav_children: {most_fav_children}")
            pos[parent.sha]['fav_children_lol'] = most_fav_children
        elif second_most_fav_children_but_still_loved_tho:
            logging.info(f"second_most_fav_children_but_still_loved_tho: {second_most_fav_children_but_still_loved_tho}")
            pos[parent.sha]['fav_children_lol'] = second_most_fav_children_but_still_loved_tho
        elif somehow_still_hanging_on_children:
            logging.info(f"somehow_still_hanging_on_children: {somehow_still_hanging_on_children}")
            pos[parent.sha]['fav_children_lol'] = somehow_still_hanging_on_children
        logging.info(f"added fav children lol: {pos[parent.sha]['fav_children_lol']}")
    else:
        logging.info(f"fav children lol already exists: {pos[parent.sha]['fav_children_lol']}")

    return actually_add_childs_connections(commit,parent,grid,pos,parents_indicies)

def make_commit_tree(repo: Repo, commits: list[Commit], time_window_timestamp: int):

    grid = []
    pos = {}
    print(f"len(commits):{len(commits)}")
    for commit in commits:
        #if commit.id == 4:
        #    break
        print(f"STARTING LOOP with idx--------------------------------------------------")
        logging.info(f"commit: {commit}")
        logging.info(f"sha: {commit.sha}")
        logging.info(f"commit's branch: {commit.branch.name}")
        logging.info(f"commit's creation_timestamp: {commit.creation_timestamp}")
        # let's check here if commit belongs to main or dev branches
        main_or_dev = False
        if commit.branch.name == repo.main_branch_name or commit.branch.name == repo.dev_branch_name:
            main_or_dev = True
        logging.info(f"commit's main_or_dev: {main_or_dev}")


        if len(commit.parents) == 0 or (len(commit.parents) == 1 and commit.parents[0].creation_timestamp <= time_window_timestamp):
            if len(commit.parents) == 0:
                logging.info("parents == 0")
            else:
                logging.info("parents == 1 and parents[0].creation_timestamp <= time_window_timestamp")
            last_empty_space_idx = 0
            logging.info(f"col:{last_empty_space_idx}") 
            if not grid:
                logging.info("grid doesn't yet exist")
                commit_row = []

                logging.info(f"commit.branch.name: {commit.branch.name}")
                logging.info(f"repo.main_branch_name: {repo.main_branch_name}")
                if commit.branch.name == repo.main_branch_name:
                    logging.info("commit is on main branch")
                    commit_row = [commit]
                    last_empty_space_idx = 0
                elif commit.branch.name == repo.dev_branch_name:
                    logging.info("commit is on dev branch")
                    commit_row = [None,commit]
                    last_empty_space_idx = 1
                else:
                    logging.info("commit is on neither main or dev branch")
                    commit_row = [None,None,commit]
                    last_empty_space_idx = 2

                logging.info(f"last_empty_col_idx: {last_empty_space_idx}")
                grid.append(commit_row)
                logging.info(f"putting col to {last_empty_space_idx} with {commit.sha}")
                pos[commit.sha] = {'col':last_empty_space_idx, 'row':0, 
                                   'children_so_far':0,'above_used':False,
                                   'fav_children_lol':[]}
            else:
                logging.info("grid exists")
                            
                logging.info(f"commit.branch.name: {commit.branch.name}")
                if commit.branch.name == repo.main_branch_name:
                    logging.info("commit is on main branch")
                    last_empty_col_idx = 0
                elif commit.branch.name == repo.dev_branch_name:
                    logging.info("commit is on dev branch")
                    last_empty_col_idx = 1
                else:
                    logging.info("commit is on neither main or dev branch")
                    last_empty_col_idx = len(grid[-1]);
                    for i in range(len(grid[-1])-1,-1,-1):
                        if grid[-1][i]:
                            break
                        else:
                            last_empty_col_idx = i
                logging.info(f"last_empty_col_idx: {last_empty_col_idx}")
                if last_empty_col_idx == len(grid[-1]):
                    logging.info("adding empty col to the end of every row")
                    for i in range(len(grid)):
                        if i % 2 == 0:
                            grid[i].append(None)
                        else:
                            grid[i].append([])

                connect_row = []
                for col_ in grid[-1]:
                    connect_row.append([])
                grid.append(connect_row)
                commit_row = []
                for i in range(len(grid[-1])):
                    if i == last_empty_col_idx: 
                        commit_row.append(commit)
                    else:
                        commit_row.append(None)
                grid.append(commit_row)
                pos[commit.sha] = {'col':last_empty_col_idx, 'row':len(grid)-1, 
                                   'children_so_far':0,'above_used':False,
                                   'fav_children_lol':[]}
                logging.info(f"leaving zero parents with {commit.sha}: {pos[commit.sha]}")

        elif len(commit.parents) == 1:
            logging.info("parents == 1")
            logging.info(f"commit.parents[0].sha:{commit.parents[0].sha}")
            logging.info(f"commit.parents[0]: {commit.parents[0]}")
            childs_col_idx = add_childs_connection_to_parent(commit,commit.parents[0],grid,pos)
            if len(grid) % 2 == 1: # connect_row didn't get added since parent wasn't on the last row
                logging.info("connect_row didn't get added so adding it here")
                # grid[-1] is commit row btw
                connect_row = []
                for i in range(len(grid[-1])):
                    if i == childs_col_idx:
                        connect_row.append(['through'])
                    else:
                        connect_row.append([])
                grid.append(connect_row)

            logging.info(f"checking if commit is on main/dev branch and has no fav children anymore")
            parent_col = pos[commit.parents[0].sha]['col']
            if repo.main_branch_in_use and childs_col_idx != 0 and commit.branch.name == repo.main_branch_name \
                    and len(pos[commit.parents[0].sha]['fav_children_lol']) == 0:
                logging.info("commit is on main branch - adding to the index 0 no matter what")
                logging.info("adding commit row in between")
                commit_row = []
                for i in range(len(grid[-1])):
                    if i == childs_col_idx:
                        commit_row.append('line-through')
                    else:
                        commit_row.append(None)
                grid.append(commit_row)

                   
                if childs_col_idx > 0:
                    logging.info("childs_col_idx more than zero")
                    connect_row = []
                    for i in range(len(grid[-1])):
                        if i == 0:
                            connect_row.append(['from-left'])
                        elif i == childs_col_idx:
                            connect_row.append(['to-right'])
                        elif 0 < i < childs_col_idx:
                            connect_row.append(['horizontal'])
                        else:
                            connect_row.append([])
                    grid.append(connect_row)
                else:
                    logging.error("shouldn't go here in the else, child_col_idx is 0 or lower")
                    return "fail on main branch commit going into else"

                childs_col_idx = 0


            elif repo.dev_branch_in_use and childs_col_idx > 1 and commit.branch.name == repo.dev_branch_name \
                    and len(pos[commit.parents[0].sha]['fav_children_lol']) == 0:
                logging.info("commit is on dev branch - adding to the index 1 no matter what")
                logging.info("adding commit row in between")
                commit_row = []
                for i in range(len(grid[-1])):
                    if i == childs_col_idx:
                        commit_row.append('line-through')
                    else:
                        commit_row.append(None)
                grid.append(commit_row)

                   
                logging.info("adding connect_row for dev branch commit")
                if childs_col_idx > 1: # on the left side of 1
                    logging.info(f"on the left side of dev")
                    connect_row = []
                    for i in range(len(grid[-1])):
                        if i == 1:
                            connect_row.append(['from-left'])
                        elif i == childs_col_idx:
                            connect_row.append(['to-right'])
                        elif 0 < i < childs_col_idx:
                            connect_row.append(['horizontal'])
                        else:
                            connect_row.append([])
                    grid.append(connect_row)
                else: # on right side of dev(on top of main)
                    logging.info(f"on the right side of dev")
                    connect_row = []
                    for i in range(len(grid[-1])):
                        if i == 0:
                            connect_row.append('to-left')
                        elif i == 1:
                            connect_row.append('from-right')
                        else:
                            connect_row.append([])
                    grid.append(connect_row)

                childs_col_idx = 1

            logging.info("survived the if else for main/dev branch commits")
            
            commit_row = []
            for i in range(len(grid[-1])):
                if i == childs_col_idx:
                    commit_row.append(commit)
                else:
                    commit_row.append(None)
            grid.append(commit_row)
            pos[commit.sha] = {'col':childs_col_idx,'row':len(grid)-1,
                               'children_so_far':0,'above_used':False,
                               'fav_children_lol':[]}
            logging.info(f"leaving one parent with {commit.sha}: {pos[commit.sha]}")

        else: # merge commit
            logging.info("merge commit")
            parents_indicies = []
            for parent in commit.parents:
                logging.info(f"parent: {parent}")

                parent_in_the_timewindow = parent.creation_timestamp > time_window_timestamp
                if parent_in_the_timewindow:
                    logging.info(f"parent:{parent.sha[:6]} IS in the time window")
                    childs_col_idx = add_childs_connection_to_parent(commit,parent,grid,pos,parents_indicies) 
                    parents_indicies.append(childs_col_idx)
                else:
                    logging.info(f"parent:{parent.sha[:6]} IS NOT in the time window")
            logging.info(f"parents_indicies:{parents_indicies}")

            if len(grid) % 2 == 1: # connect_row didn't get added since none of the parents were on the last row
                logging.info("adding connect row since none of the parents were on the last row")
                connect_row = []
                for i in range(len(grid[-1])):
                    if i in parents_indicies:
                        connect_row.append(["through"])
                    else:
                        connect_row.append([])
                grid.append(connect_row)

            logging.info("adding commit row in between before merge connect row")
            commit_row = []
            for i in range(len(grid[-1])):
                if i in parents_indicies:
                    commit_row.append('line-through')
                else:
                    commit_row.append(None)
            grid.append(commit_row)

            parents_indicies = sorted(parents_indicies)

            if repo.main_branch_in_use and parents_indicies[0] != 0 and commit.branch.name == repo.main_branch_name:
                logging.info("commit is on main branch and not on the right column")
                merge_connect_row = []
                for i in range(len(grid[-1])):
                    if i in parents_indicies:
                        merge_connect_row.append(['to-right'])
                    elif i == 0:
                        merge_connect_row.append(['from-left'])
                    else:
                        merge_connect_row.append([])

                # filling the holes
                for i in range(1,parents_indicies[-1]):
                    if merge_connect_row[i]:
                        merge_connect_row[i].append('horizontal')
                    else:
                        merge_connect_row[i] = ['horizontal']
                logging.info(f"merge_connect_row:{merge_connect_row}")
                grid.append(merge_connect_row)

                logging.info("adding commit row")
                commit_row = []
                for i in range(len(grid[-1])):
                    if i == 0:
                        commit_row.append(commit)
                    else:
                        commit_row.append(None)
                grid.append(commit_row)
    
                pos[commit.sha] = {'col':0,'row':len(grid)-1,
                               'children_so_far':0,'above_used':False,
                               'fav_children_lol':[]}

            elif repo.dev_branch_in_use and parents_indicies[0] > 1 and commit.branch.name == repo.dev_branch_name:
                logging.info("commit is on dev branch and not on the right column")
                merge_connect_row = []
                for i in range(len(grid[-1])):
                    if i in parents_indicies:
                        merge_connect_row.append(['to-right'])
                    elif i == 1:
                        merge_connect_row.append(['from-left'])
                    else:
                        merge_connect_row.append([])

                # filling the holes
                for i in range(2,parents_indicies[-1]):
                    if merge_connect_row[i]:
                        merge_connect_row[i].append('horizontal')
                    else:
                        merge_connect_row[i] = ['horizontal']
                logging.info(f"merge_connect_row:{merge_connect_row}")
                grid.append(merge_connect_row)

                logging.info("adding commit row")
                commit_row = []
                for i in range(len(grid[-1])):
                    if i == 1:
                        commit_row.append(commit)
                    else:
                        commit_row.append(None)
                grid.append(commit_row)
    
                pos[commit.sha] = {'col':1,'row':len(grid)-1,
                               'children_so_far':0,'above_used':False,
                               'fav_children_lol':[]}
            else: # no need to move the commit to main or dev columns so putting it one the most rightest(word(?)) parent column
                # let's just put the commit on top of the right most parent for now
                logging.info("no need to move the commit to main or dev columns so putting it one the most rightest(word(?)) parent column")
                merge_connect_row = []
                for i in range(len(grid[-1])):
                    if i in parents_indicies:
                        if i == parents_indicies[0] and len(parents_indicies) > 1:
                            merge_connect_row.append(['through','from-left'])
                        elif i == parents_indicies[0]:
                            merge_connect_row.append(['through'])
                        else:
                            merge_connect_row.append(['to-right'])
                        continue
                    else:
                        merge_connect_row.append([])

                logging.info(f"parent_indicies:{parents_indicies}")
                for i in range(parents_indicies[0]+1,parents_indicies[-1]):
                    if merge_connect_row[i]:
                        merge_connect_row[i].append('horizontal')
                    else:
                        merge_connect_row[i] = ['horizontal']
                logging.info(f"merge_connect_row:{merge_connect_row}")
                grid.append(merge_connect_row)

                logging.info("adding commit row")
                commit_row = []
                for i in range(len(grid[-1])):
                    if i == parents_indicies[0]:
                        commit_row.append(commit)
                    else:
                        commit_row.append(None)
                grid.append(commit_row)

                pos[commit.sha] = {'col':parents_indicies[0],'row':len(grid)-1,
                                   'children_so_far':0,'above_used':False,
                                   'fav_children_lol':[]}

        print("ENDING LOOP --------------------------------------------------")

    for col_idx in range(len(grid[-1])):
        empty_last_col = True
        for row in grid:
            if row[-1]: 
                empty_last_col = False
                break
        if empty_last_col:
            logging.info(f"removing last col: {col_idx}")
            for row in grid:
                row.pop()


    width = len(grid[0])
    grid.reverse()
    min_number_of_cols = 7
    for row in grid:
        if len(row) < min_number_of_cols:
            row += [None] * (min_number_of_cols - len(row))
        row.reverse()
        print(row)


    return grid


def get_latest_post(user: User):
    latest_post = Post.query.join(Repo).filter(
        (Post.user_id == user.id) & 
        (Post.not_finished == False) & 
        (Repo.private == False) 
    ).order_by(
        Post.creation_timestamp.desc()
    ).first()

    if latest_post is None:
        return None

    return latest_post


def update_user_widget_settings(widget_type, fill_color, stroke_color, text_color):
    if widget_type == 'markdown':
        current_user.settings.markdown_widget_fill_color = fill_color
        current_user.settings.markdown_widget_stroke_color = stroke_color
        current_user.settings.markdown_widget_text_color = text_color
    db.session.commit()


def make_widget(user: User, latest_posts_count: int, fill_color: str, stroke_color: str, text_color: str):
    """
    Generates an SVG widget for the user's recent posts.
    :param user: The user to generate the widget for.
    :param latest_posts_count: The number of posts to include in the widget.
    :param fill_color: The background color of the widget in hex.
    :param stroke_color: The border color of the widget in hex.
    :param text_color: The text color of the widget in hex.
    :return: The SVG widget as a string.
    """

    def wrap_text(text, max_length):
        escaped_content = text.replace('<', '&lt;').replace('>', '&gt;')
        words = escaped_content.split(' ')
        lines = []
        current_line = []

        for word in words:
            if len(' '.join(current_line) + ' ' + word) <= max_length:
                current_line.append(word)
            else:
                lines.append(' '.join(current_line))
                current_line = [word]

        lines.append(' '.join(current_line))
        return lines

    def url_to_base64(url):
        response = requests.get(url)
        return base64.b64encode(response.content).decode()

    
    latest_posts = Post.query.join(Repo).filter(
                (Post.user_id == user.id) & 
                (Post.not_finished == False) & 
                (Repo.private == False)
            ).order_by(
                Post.creation_timestamp.desc()
            ).limit(
                latest_posts_count
            ).all()

    # Initialize SVG header
    svg_height = 80  # 50 for the header, 30 for the footer
    svg_parts = []
    svg_parts.append(f'<svg width="400" height="{svg_height}" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">')
    svg_parts.append(f'<rect x="0" y="0" width="400" height="{svg_height}" fill="{text_color}"/>')
    svg_parts.append(f'<text x="10" y="30" font-family="Verdana" font-size="16" fill="{fill_color}">Recent Activity</text>')

    y_position = 50  # Starting Y-coordinate for the text

    for post in latest_posts:
        base_64_string1 = url_to_base64(post.user.github_avatar_url)
        max_length = 50  # Maximum characters per line
        wrapped_content = wrap_text(post.content_decrypted, max_length)
        post_height = 40 + len(wrapped_content) * 16 + 40  # 40 for the header, 16 per line, 20 for the date

        # Update the SVG height
        svg_height += post_height + 10  # 10 for padding between posts
        #232626
        # Add the post to the SVG
        svg_parts.append(f'<rect x="10" y="{y_position}" rx="5" ry="5" width="380" height="{post_height}" style="fill:{fill_color};stroke-width:1;stroke:{stroke_color}" />')
        svg_parts.append(f'<image x="20" y="{y_position + 10}" width="40" height="40" xlink:href="data:image/png;base64,{base_64_string1}"/>')
        svg_parts.append(f'<text x="70" y="{y_position + 20}" font-family="Verdana" font-size="14" fill="{text_color}">{post.user.name}</text>')
        svg_parts.append(f'<text x="70" y="{y_position + 36}" font-family="Verdana" font-size="12" fill="{text_color}">in {post.repo.name}</text>')
        
        for i, line in enumerate(wrapped_content):
            y_line_position = y_position + 60 + (i * 16)
            svg_parts.append(f'<text x="70" y="{y_line_position}" font-family="Verdana" font-size="12" fill="{text_color}">{line}</text>')
        
        post_date = humanize.naturaltime(datetime.now() - datetime.fromtimestamp(post.creation_timestamp))
        svg_parts.append(f'<text x="70" y="{y_position + post_height - 10}" font-family="Verdana" font-size="10" fill="{text_color}">{post_date}</text>')
        
        y_position += post_height + 10  # Increment Y-coordinate for the next post

    svg_parts.append(f'<text x="10" y="{svg_height - 10}" font-family="Verdana" font-size="12" fill="{fill_color}">Powered by PacePeek.com</text>')

    # Close SVG and update the height
    svg_parts.append(f'</svg>')
    svg = ''.join(svg_parts).replace(f'height="{80}"', f'height="{svg_height}"')
    return svg



def set_last_seen_posts_for_new_following(followed: User):
    """
    When a user follows another user, we need to set the last seen post for each repo of the followed user to the latest post.
    """
    followed_repos = Repo.query.filter_by(owner_github_login=followed.github_login).all()
    
    for repo in followed_repos:
        latest_post = Post.query.filter_by(repo_id=repo.id).order_by(Post.creation_timestamp.desc()).first()
        
        last_seen_record = UserRepoLastSeen.query.filter_by(
            user_id=current_user.id, 
            repo_id=repo.id
        ).first()
        
        if last_seen_record:
            last_seen_record.last_seen_post_id = latest_post.id if latest_post else 0
        else:
            new_record = UserRepoLastSeen(
                user_id=current_user.id,
                repo_id=repo.id,
                last_seen_post_id=latest_post.id if latest_post else 0
            )
            db.session.add(new_record)
    
    db.session.commit()



def get_next_posts():
    oldest_post_time = session.get("oldest_post_time",default=datetime.now(ZoneInfo("UTC")))
    all_legal_posts = []
    for user in current_user.followers:
        user_posts = Post.query.filter((Post.user_id == user.id) & (Post.time_stamp > oldest_post_time)).all()

        all_legal_posts.append(user_posts)

    next_posts = []
    next_posts = sorted(next_posts, key=lambda x: x.time_stamp, reverse=True)[:5]

    if next_posts:
        session['oldest_post'] = next_posts[-1].time_stamp.timestamp()
    return next_posts


def get_repos_for_user():
    from .github_utils import validate_user_access_token
    validate_user_access_token()
    headers = {'Authorization': f'token {current_user.github_user_access_token_decrypted}'}
    existing_repos = [repo.name for repo in Repo.query.filter_by(owner_github_id=current_user.github_id).all() if not repo.deleted]
    repos_list = []
    page = 1

    while True:
        try:
            response = requests.get(f'https://api.github.com/users/{current_user.github_login}/repos?page={page}&per_page=100', headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            log_the_error_context(e,150, f"Error fetching repos for user: {current_user.github_login} in get_repos_for_user function")
            print(f"Error fetching repos: {e}")
            return None

        repos_data = response.json()
        if not repos_data:
            break  # No more repositories
        pprint(repos_data)

        for repo in repos_data:
            repo_details = {
                'name': repo['name'],
                'github_id': repo['id'],
                'owner_id': repo['owner']['id'],
                'private': repo['private'],
            }
            if repo['name'] not in existing_repos:
                if current_user.is_premium:
                    repos_list.append(repo_details)
                elif repo['private'] == False: # not premium users can only track public repos
                    repos_list.append(repo_details)

        # Check if there are more pages
        link_header = response.headers.get('Link', '')
        if 'rel="next"' not in link_header:
            break  # No more pages

        page += 1  # Increment the page number for the next loop

    logging.info(f"leaving get_repos_for_user with repos_list:{repos_list}")
    return repos_list

def get_last_four_posts(repo: Repo, latest_post: Post):
    """
    Get's the last four posts from the latest post according to post.creation_timestamp which is in seconds
    """
    last_four_posts = Post.query.filter_by(repo=repo).filter(Post.creation_timestamp < latest_post.creation_timestamp).order_by(Post.creation_timestamp.desc()).limit(4).all()
    return last_four_posts

    

def get_last_four_parent_commits(repo: Repo, commit: Commit):
    """
    Get's the last four parents from the latest commit with bfs style.
    This is used for giving context for analyzing the current commit.
    """
    from collections import deque
    q = deque([commit])
    commits = []
    while q:
        current_commit = q.popleft()
        if current_commit.parents:
            for parent in current_commit.parents:
                if len(commits) == 4:
                    # sort to descending order
                    commits.sort(key=lambda x: x.creation_timestamp, reverse=True)
                    summaries = [commit.post.content_decrypted for commit in commits]
                    return summaries
                commits.append(parent)
                q.append(parent)
    return []



def get_file_analysis_method(filename: str, code: str, repo: Repo):

    # so here's a list of all the file endings currently supported
    possible_files = [
        ".py", ".js", ".ts", ".html", ".css", ".scss", ".sass", ".less", 
        ".php", ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".go", ".rs", 
        ".swift", ".kt", ".ktm", ".kts", ".clj", ".cljs", ".cljc", ".groovy", 
        ".scala", ".sc", ".lua", ".rb", ".r", ".dart", ".sh", ".bash", ".zsh", 
        ".fish", ".ps1", ".bat",
        ".xml", ".json", ".yaml", ".yml", ".md", ".markdown", ".tex", ".sql", 
        ".pl", ".pm", ".t", ".pod", ".m", ".mm", ".pyc", ".pyx", ".pxd", ".pxi", 
        ".f", ".for", ".f90", ".f95", ".asm", ".s", ".vbs", ".vba", ".awk", ".sed", 
        ".ml", ".mli", ".fs", ".fsi", ".fsx", ".fsscript", ".v", ".vhdl", ".verilog", 
        ".sv", ".svh", ".tcl", ".exp", ".makefile", ".cmake", ".dockerfile", ".ini", 
        ".cfg", ".conf", ".erl", ".hrl", ".ex", ".exs", ".hs", ".lhs", ".jl", ".p6", 
        ".pl6", ".pm6", ".nim", ".cr", ".ktn", ".x86", ".arm", ".mips", ".wasm", 
        ".idl", ".proto", ".thrift", ".graphql", ".gql"
    ]

    # to block off cache files, binary files, data files, and other files that are not code files written by human
    unsupported_file_endings = [
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".ico", ".svg", ".webp", 
        ".mp4", ".webm", ".ogg", ".mp3", ".wav", ".flac", ".aac", ".wma", ".m4a", 
        ".flv", ".avi", ".mov", ".wmv", ".mkv", ".mpg", ".mpeg", ".m4v", ".3gp", ".3g2", 
        # Binary or compiled files
        ".exe", ".dll", ".so", ".o", ".a", 
        # Archive files
        ".zip", ".tar", ".rar", ".gz", ".bz2", ".7z", 
        # Temporary or backup files
        ".tmp", ".temp", ".bak", ".backup", ".swp", 
        # Log files
        ".log", 
        # Environment and configuration files might be excluded based on your specific needs
        ".env", ".env.local", ".env.development", ".env.test", ".env.production", 
        ".env.development.local", ".env.test.local", ".env.production.local", 
        # Lock files
        ".lock"
    ]

    logging.info(f"filename: {filename}")
    if '.' not in filename:
        extension = "None"
    else:
        extension = "." + filename.split('.')[-1]
    print("extension:", extension)
    filetype = Filetype.query.filter_by(extension=extension, repo=repo).first()
    if not filetype:
        logging.info(f"Filetype not found for extension: {extension}")
        if extension in possible_files:
            logging.info(f"extension: {extension} is in possible_files")
            filetype = Filetype(extension=extension, analyze_decision="full", repo_id=repo.id)
            db.session.add(filetype)
            db.session.commit()
            return 'full'
        if extension in unsupported_file_endings:
            logging.info(f"extension: {extension} is in unsupported_file_endings")
            filetype = Filetype(extension=extension, analyze_decision="never", repo_id=repo.id)
            db.session.add(filetype)
            db.session.commit()
            return 'never'
        if extension == "None":
            logging.info(f"extension: {extension} is None")
            filetype = Filetype(extension=extension, analyze_decision="always_check", repo_id=repo.id)
            db.session.add(filetype)
            db.session.commit()
            return 'always_check'
        # analyze the beginning
        analyze_decision, tokens_used = analyze_first_25_lines_of_code(filename, code)
        logging.info(f"analyze_decision: {analyze_decision}")
        if analyze_decision == 'full':
            filetype = Filetype(extension=extension, analyze_decision="full", repo_id=repo.id)
            db.session.add(filetype)
            db.session.commit()
            return 'full'
        if analyze_decision == 'beginning':
            filetype = Filetype(extension=extension, analyze_decision="beginning", repo_id=repo.id)
            db.session.add(filetype)
            db.session.commit()
            return 'beginning'
        if analyze_decision == 'never':
            filetype = Filetype(extension=extension, analyze_decision="never", repo_id=repo.id)
            db.session.add(filetype)
            db.session.commit()
            return 'never'
        if analyze_decision == 'always_check':
            filetype = Filetype(extension=extension, analyze_decision="always_check", repo_id=repo.id)
            db.session.add(filetype)
            db.session.commit()
            return 'always_check'
        create_admin_notification(f"Filetype not found for extension: {extension}")

    else: # filetype exists
        if filetype.analyze_decision == 'full':
            return 'full'
        if filetype.analyze_decision == 'beginning':
            return 'beginning'
        if filetype.analyze_decision == 'never':
            return 'never'
        if filetype.analyze_decision == 'always_check':
            analyze_decision, tokens_used = analyze_first_25_lines_of_code(filename, code)
            if analyze_decision == 'full':
                return 'full'
            if analyze_decision == 'beginning':
                return 'beginning'
            if analyze_decision == 'never':
                return 'never'
        create_admin_notification(f"Invalid analyze_decision for filetype: {filetype.analyze_decision}")
        return 'fail'

      
