import os
import time
import secrets
from dotenv import load_dotenv,set_key

from dotenv import set_key

env_path = '.env'

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")

KEY_EXP = os.getenv("KEY_EXP")


def did_key_exp():

	current_time = int(time.time())

	if current_time > int(KEY_EXP):

		set_key(env_path,'SECRET_KEY',secrets.token_urlsafe(32))
		
		six_months_later_delta =  24 * 60 * 60 * 30 * 6
		
		set_key(env_path,'KEY_EXP',str(current_time + six_months_later_delta))


def main():

	print(type(KEY_EXP))

	did_key_exp()

if __name__=="__main__":
	main()
