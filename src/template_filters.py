from datetime import datetime
from babel.dates import format_datetime
import logging
from flask import Blueprint , session
from flask_login import current_user
from zoneinfo import ZoneInfo
from . import get_locale
import humanize

template_filters = Blueprint('template_filters', __name__)

@template_filters.app_template_filter('timestamp_to_user_localtime')
def timestamp_to_user_localtime_datetime(timestamp: int):
    if not current_user.is_authenticated:
        return datetime.fromtimestamp(timestamp, tz=ZoneInfo('UTC'))
    return datetime.fromtimestamp(timestamp, tz=ZoneInfo(current_user.timezone))

@template_filters.app_template_filter('naturaldate')
def naturaldate(date_in_user_timezone):
    return date_in_user_timezone.strftime('%d %b %Y')

@template_filters.app_template_filter('pretty_hour_time')
def pretty_hour_time(date_in_user_timezone):
    nat_t = date_in_user_timezone.strftime('%H:%M:%S')
    return nat_t

@template_filters.app_template_filter('pretty_day_time_with_weekday')
def pretty_day_time(date_in_user_timezone):
    formatted_date = format_datetime(date_in_user_timezone, format='long', locale=get_locale())
    return formatted_date

@template_filters.app_template_filter('pretty_time')
def pretty_time(date_in_user_timezone):
    nat_d = date_in_user_timezone.strftime('%d %b %Y')
    nat_t = date_in_user_timezone.strftime('%H:%M:%S')
    return f"{nat_d} {nat_t}"

@template_filters.app_template_filter('time_ago')
def time_ago(zone_aware_date_in_user_timezone):
    if not current_user.is_authenticated:
        timezone = ZoneInfo('UTC')
        if session.get('locale') == "fi":
            logging.warning(f"Locale in session: {session['locale']}")
            _t = humanize.i18n.activate(session['locale'])
        else:
            logging.warning("No locale in session, using en")
    else:
        timezone = ZoneInfo(current_user.timezone)
        logging.warning(f"User's timezone: {current_user.timezone}")
        logging.warning(f"User's locale: {current_user.locale}")
        if current_user.locale != "en":
            _t = humanize.i18n.activate(current_user.locale)
    diff = humanize.naturaltime(datetime.now(timezone) - zone_aware_date_in_user_timezone)
    _t = humanize.i18n.deactivate()
    return diff
    
