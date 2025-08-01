sudo apt-get install python3-dev default-libmysqlclient-dev build-essential


CREATE DATABASE hr_call_analysis;
CREATE USER 'root'@'localhost' IDENTIFIED BY 'root';
GRANT ALL PRIVILEGES ON hr_call_analysis.* TO 'root'@'localhost';
FLUSH PRIVILEGES;
EXIT;