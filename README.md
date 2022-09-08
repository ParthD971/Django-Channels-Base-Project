# Django-Channels-Base-Project

## To use accounts app

### To install redis server
    sudo apt install redis

### To start redis server
    redis-server

### To install redis server
    service redis-server stop

### To restart redis server
    service redis-server restart

### To check status of redis server
    service redis-server status

### To start celery
    celery -A core worker --pool=solo -l info
    celery -A core worker -l info
    celery -A core worker