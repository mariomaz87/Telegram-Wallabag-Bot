# Telegram-Wallabag-Bot
A self-hosted Telegram bot that posts received URL as articles in your wallabag instance.
You can provide tags (if any) in the same message after the URL or in a next message in the next 5 seconds, comma-separated.

# Instructions
Download the files from the repo ("git clone https://github.com/mariomaz87/Telegram-Wallabag-Bot"), modify example.env with your details, rename it to ".env" and deploy with:

docker-compose build

docker-compose up -d

The optional WALLABAG_ARCHIVE variable defaults to 1 for auto archive. You can set it to 0 to avoid archiving the entries automatically.
