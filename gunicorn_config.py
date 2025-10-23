# gunicorn_config.py
bind = "0.0.0.0:8080"
# The number of worker processes. A good starting point is (2 x $num_cores) + 1.
workers = 3
# Log to stdout and stderr, which is standard for containers.
accesslog = "-"
errorlog = "-"
loglevel = "info"
