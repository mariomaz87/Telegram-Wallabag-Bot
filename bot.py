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

if not all([TELEGRAM_TOKEN, MY_CHAT_ID, WALLABAG_URL, WALLABAG_CLIENT_ID, WALLABAG_CLIENT_SECRET,
            WALLABAG_USERNAME, WALLABAG_PASSWORD]):
    logger.error("Missing required environment variables!")
    sys.exit(1)

def chat_id_restricted(func):
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
        logger.info("Requesting Wallabag token...")
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        return response.json()["access_token"]
    except requests.exceptions.RequestException as e:
        logger.error(f"Error requesting Wallabag token: {e}")
        raise

def is_valid_url(url: str) -> bool:
    url_regex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?))'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(url_regex, url) is not None

def is_valid_tag(tag: str) -> bool:
    # Remove any whitespace before validation
    tag = tag.strip()
    tag_regex = re.compile(r'^[a-zA-Z0-9_-]+$')
    return bool(tag) and re.match(tag_regex, tag) is not None

@chat_id_restricted
async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    message_text = update.message.text.strip()
    urls = [word for word in message_text.split() if is_valid_url(word)]
    
    if len(urls) > 1:
        await update.message.reply_text("Please provide only one URL at a time.")
        return ConversationHandler.END
    
    if not urls:
        await update.message.reply_text("No valid URL found. Please provide a valid URL.")
        return ConversationHandler.END
    
    url = urls[0]
    context.user_data['current_url'] = url
    await update.message.reply_text("Waiting 10 seconds for tags...")
    
    # Store the job in user_data so we can cancel it later
    job = context.job_queue.run_once(timeout_callback, 10, data={'chat_id': update.effective_chat.id, 'url': url})
    context.user_data['timeout_job'] = job
    
    return WAITING_FOR_TAGS

async def timeout_callback(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        # Check if the job was cancelled
        if context.job.removed:
            return
            
        chat_id = context.job.data['chat_id']
        url = context.job.data['url']
        
        class FakeUpdate:
            def __init__(self, chat_id):
                self.effective_chat = type('obj', (object,), {'id': chat_id})
                self.message = type('obj', (object,), {'reply_text': None})
            async def reply_text(self, text):
                await context.bot.send_message(chat_id=self.effective_chat.id, text=text)

        fake_update = FakeUpdate(chat_id)
        fake_update.message.reply_text = fake_update.reply_text
        await process_url_and_tags(fake_update, url, "")
    except Exception as e:
        logger.error(f"Error in timeout_callback: {e}")

@chat_id_restricted
async def handle_tags(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    url = context.user_data.get('current_url')
    if not url:
        return ConversationHandler.END
    
    # Cancel the timeout job
    if 'timeout_job' in context.user_data:
        context.user_data['timeout_job'].schedule_removal()
    
    # Split tags by both commas and spaces, and clean up
    tags_input = update.message.text.strip()
    # First split by comma, then by spaces if any
    tags_list = []
    for tag_group in tags_input.split(','):
        tags_list.extend(tag_group.split())
    # Remove empty tags and strip whitespace
    tags_list = [tag.strip() for tag in tags_list if tag.strip()]
    
    if tags_list and not all(is_valid_tag(tag) for tag in tags_list):
        await update.message.reply_text("One or more provided tags are invalid. Tags can only contain letters, numbers, underscores, and hyphens.")
        return ConversationHandler.END
    
    # Join tags with comma for Wallabag API
    tags = ','.join(tags_list)
    
    await process_url_and_tags(update, url, tags)
    context.user_data.clear()
    return ConversationHandler.END

async def process_url_and_tags(update: Update, url: str, tags: str) -> None:
    try:
        token = get_wallabag_token()
        headers = {'Authorization': f'Bearer {token}'}
        data = {'url': url, 'tags': tags, 'archive': int(WALLABAG_DEFAULT_ARCHIVE)}
        
        logger.info(f"Saving URL to Wallabag: {url} with tags: {tags}")
        response = requests.post(f'{WALLABAG_URL}/api/entries.json', headers=headers, json=data)
        
        if response.status_code == 200:
            await update.message.reply_text(f"Article saved with tags: {tags}" if tags else "Article saved without tags.")
        else:
            logger.error(f"Failed to save article. Response: {response.text}")
            await update.message.reply_text(f"Failed to save the article. Error: {response.json().get('error_description', 'Unknown error')}")
    except Exception as e:
        logger.error(f"Unexpected error saving article: {e}")
        await update.message.reply_text("An unexpected error occurred while saving the article.")

def main() -> None:
    # Create the Application and pass it your bot's token
    application = Application.builder().token(TELEGRAM_TOKEN).build()

    # Add conversation handler
    conv_handler = ConversationHandler(
        entry_points=[MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url)],
        states={
            WAITING_FOR_TAGS: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_tags)],
        },
        fallbacks=[],
    )

    application.add_handler(conv_handler)

    # Start the Bot
    logger.info("Starting bot...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
