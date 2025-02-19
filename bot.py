import os
import sys
import logging
import requests
import re
import asyncio
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import (
    Application, 
    CommandHandler, 
    MessageHandler, 
    filters, 
    ContextTypes,
    ConversationHandler
)

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# States
WAITING_FOR_TAGS = 1

# Configuration
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
MY_CHAT_ID = os.getenv("MY_CHAT_ID")
WALLABAG_URL = os.getenv("WALLABAG_URL")
WALLABAG_CLIENT_ID = os.getenv("WALLABAG_CLIENT_ID")
WALLABAG_CLIENT_SECRET = os.getenv("WALLABAG_CLIENT_SECRET")
WALLABAG_USERNAME = os.getenv("WALLABAG_USERNAME")
WALLABAG_PASSWORD = os.getenv("WALLABAG_PASSWORD")
WALLABAG_DEFAULT_ARCHIVE = os.getenv("WALLABAG_DEFAULT_ARCHIVE", "1")

# Validate required environment variables
if not all([TELEGRAM_TOKEN, MY_CHAT_ID, WALLABAG_URL, WALLABAG_CLIENT_ID, WALLABAG_CLIENT_SECRET, 
            WALLABAG_USERNAME, WALLABAG_PASSWORD]):
    logger.error("Missing required environment variables!")
    sys.exit(1)

def chat_id_restricted(func):
    """Decorator to restrict bot usage to specific chat ID"""
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        if str(update.effective_chat.id) != MY_CHAT_ID:
            logger.warning(f"Unauthorized access denied for {update.effective_chat.id}")
            await update.message.reply_text("You are not authorized to use this bot.")
            return ConversationHandler.END
        return await func(update, context, *args, **kwargs)
    return wrapped

def get_wallabag_token():
    token_url = f"{WALLABAG_URL}/oauth/v2/token"
    data = {
        "grant_type": "password",
        "client_id": WALLABAG_CLIENT_ID,
        "client_secret": WALLABAG_CLIENT_SECRET,
        "username": WALLABAG_USERNAME,
        "password": WALLABAG_PASSWORD
    }
    try:
        logger.info(f"Requesting token from {token_url} with data: {data}")
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        token = response.json()["access_token"]
        logger.info(f"Token request successful. Token: {token}")
        return token
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err.response.text}")
        raise
    except Exception as err:
        logger.error(f"Other error occurred: {err}")
        raise

def is_valid_url(url: str) -> bool:
    """Validate the provided URL"""
    url_regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(url_regex, url) is not None

def is_valid_tag(tag: str) -> bool:
    """Validate the provided tag"""
    # Assuming tags should not contain spaces and special characters
    tag_regex = re.compile(r'^[a-zA-Z0-9_-]+$')
    return re.match(tag_regex, tag) is not None

@chat_id_restricted
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /start is issued"""
    await update.message.reply_text("Send me a URL to save it to Wallabag. "
                                  "You can add tags in the same message after the URL (in a new line) "
                                  "or in a follow-up message within 10 seconds.")
    return ConversationHandler.END

async def process_url_and_tags(update: Update, url: str, tags: str) -> None:
    """Process URL and tags with Wallabag"""
    try:
        token = get_wallabag_token()
        headers = {'Authorization': f'Bearer {token}'}
        
        archive_value = 1 if WALLABAG_DEFAULT_ARCHIVE not in ["0", "1"] else int(WALLABAG_DEFAULT_ARCHIVE)
        
        data = {
            'url': url,
            'tags': tags,
            'archive': archive_value
        }
        
        response = requests.post(f'{WALLABAG_URL}/api/entries.json',
                               headers=headers,
                               json=data)
        
        if response.status_code == 200:
            if tags:
                await update.message.reply_text(f"Article saved with tags: {tags}")
            else:
                await update.message.reply_text("Article saved without tags")
        else:
            await update.message.reply_text(f"Failed to save the article. Status code: {response.status_code}")
            logger.error(f"Failed to save article. Response: {response.text}")
            
    except Exception as e:
        logger.error(f"Error saving article: {e}")
        await update.message.reply_text("An error occurred while saving the article")

@chat_id_restricted
async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle the initial URL message"""
    # Clear any previous state
    context.user_data.clear()

    message_text = update.message.text.strip()

    # Split message into lines
    lines = message_text.split('\n')
    first_line_parts = lines[0].split()
    url = first_line_parts[0].strip()

    if not is_valid_url(url):
        await update.message.reply_text("The provided URL is invalid. Please provide a valid URL.")
        return ConversationHandler.END
    
    # Store URL in context
    context.user_data['current_url'] = url

    # Check for tags in the same line after the URL
    if len(first_line_parts) > 1:
        tags = " ".join(first_line_parts[1:]).strip()
        if not is_valid_tag(tags):
            await update.message.reply_text("One or more provided tags are invalid. Please provide valid tags.")
            return ConversationHandler.END
        await process_url_and_tags(update, url, tags)
        context.user_data.clear()  # Clear state after processing
        return ConversationHandler.END
    # Check for tags in next line
    elif len(lines) > 1:
        tags = lines[1].strip()
        if not is_valid_tag(tags):
            await update.message.reply_text("One or more provided tags are invalid. Please provide valid tags.")
            return ConversationHandler.END
        await process_url_and_tags(update, url, tags)
        context.user_data.clear()  # Clear state after processing
        return ConversationHandler.END
    else:
        # Wait for potential tags
        await update.message.reply_text("Waiting 10 seconds for tags...")
        context.job_queue.run_once(
            callback=timeout_callback, 
            when=10, 
            data={'update': update, 'url': url},
            name='timeout'
        )
        return WAITING_FOR_TAGS

@chat_id_restricted
async def handle_tags(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle the tags message"""
    url = context.user_data.get('current_url')
    if not url:  # If no URL in context, ignore
        return ConversationHandler.END
        
    tags = update.message.text.strip()
    
    # Remove the scheduled timeout job
    current_jobs = context.job_queue.get_jobs_by_name('timeout')
    for job in current_jobs:
        job.schedule_removal()
    
    await process_url_and_tags(update, url, tags)
    context.user_data.clear()  # Clear state after processing
    return ConversationHandler.END

async def timeout_callback(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle timeout when no tags are provided"""
    job = context.job
    update = job.data['update']
    url = job.data['url']
    
    await process_url_and_tags(update, url, "")
    context.application.user_data[update.effective_user.id].clear()  # Clear state after timeout

@chat_id_restricted
async def timeout(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle timeout when waiting for tags"""
    url = context.user_data.get('current_url')
    await process_url_and_tags(update, url, "")
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancel the conversation"""
    await update.message.reply_text("Operation cancelled.")
    return ConversationHandler.END

def main() -> None:
    """Start the bot"""
    try:
        logger.info("Starting bot...")
        # Initialize with job queue
        application = (
            Application.builder()
            .token(TELEGRAM_TOKEN)
            .build()
        )
        
        # Add error handler
        application.add_error_handler(error_handler)

        # Add conversation handler
        conv_handler = ConversationHandler(
            entry_points=[MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url)],
            states={
                WAITING_FOR_TAGS: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, handle_tags),
                ]
            },
            fallbacks=[CommandHandler("cancel", cancel)]
        )

        # Add handlers
        application.add_handler(CommandHandler("start", start))
        application.add_handler(conv_handler)

        # Start the bot
        application.run_polling()

    except Exception as e:
        logger.error(f"Error running bot: {e}")
        sys.exit(1)

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle errors"""
    logger.error(f"Exception while handling an update: {context.error}")

if __name__ == '__main__':
    main()
