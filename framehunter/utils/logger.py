import logging
import os

log_directory = 'logs'
log_file = os.path.join(log_directory, 'framehunter.log')

if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filemode='w'
)

logger = logging.getLogger(__name__)