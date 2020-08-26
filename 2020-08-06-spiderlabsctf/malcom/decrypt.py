##############################
## Written by: Cooper
## CTF: SPIDERLABSCTF
## * this script can take a while to run and does generate tmp files
## * If you need to force quit mid-run, paste in diff terminal
## for x in $(ps -u $USER | grep python | cut -d " " -f 4); do kill -9 $x; done
##############################

##############################
## Imports
##############################
from Crypto.Cipher import AES
import multiprocessing as mp
import os
from struct import pack
from subprocess import Popen, PIPE, check_output
from time import time

##############################
## Given Variables
##############################
ct_hex = '1ae4c56852fde8ca7ec9823587550aa2be3c839caa0a565c6a299e7a5e2cc9998302960abc778ba3ee3c8ad0518b1edae12e4a387fbfcfa25e7b0e249a17ff61'
ct = ct_hex.decode('hex')

pt = 'Well done! your flag is: <redacted>'
ct_match_len = 20	# This is the rough length of 'Well done! your flag is:' as this is the piece of ct that we are looking for in our meet-in-the-middle attack.
			# The rest of the ct will not match becasue we are using garbage '<redacted>' for the encryptions

GOAL = 16777215 # FF FFFF
offset = 0

GOAL = 15626165 - 13896922	#TODO Remove this line, added to reduce time for demo purposes
offset = 13896922		#TODO Remove this line, added to reduce time for demo purposes

##############################
## Other Variables and methods
##############################
CPUS = mp.cpu_count()
BS = AES.block_size
pad = lambda s: s + '\x00' * (BS - len(s) % BS)

def consolidate_results(output, filename):
	with open(filename, 'w') as f:
		while True:
			m = output.get()
			if m == 'kill':
				break
			f.write(str(m))
			f.flush

def attempt_meet_in_middle(job, output_e, output_d):
	try:
		# up side encryptions
		print("\t[Thread] Starting additional encryption...")
		lib_entries = ''
		for h in range(job[0], job[1]):
			key = pack('<I', h)
			key = pad(key)

			cryptor = AES.new(key, AES.MODE_ECB)
			pt_1 = cryptor.encrypt(pad(pt))

			lib_entries += str(pt_1.encode('hex')[:ct_match_len]+":"+str(h))+'\n'	#These two line are kinda bad but done for time
		output_e.put(lib_entries)							#

		# down side decryptions
		print("\t[Thread] Starting additional decryption...")
		lib_entries = ''
		for h in range(job[0], job[1]):
			key = pack('<I', h)
			key = pad(key)

			cryptor = AES.new(key, AES.MODE_ECB)
			pt_1 = cryptor.decrypt(ct)

			lib_entries += str(pt_1.encode('hex')[:ct_match_len]+":"+str(h))+'\n'	#These two line are kinda bad but done for time
		output_d.put(lib_entries)							#

		print("\t[Thread] Libraries growing...")
	except Exception as e:
		print(e)
		pass

##############################
## Main Start Here
##############################
def main():
	divisions = []
	split_work = int(GOAL / (CPUS-2))
	start = 0
	start = offset
	for i in range(0, CPUS-2):
		divisions.append([start, start+split_work+1])
		start += split_work+1

	myList = list(divisions)
	print('[Main] Key divisions: ' + str(myList))

	manager = mp.Manager()
	output_e = manager.Queue()
	output_d = manager.Queue()
	pool = mp.Pool(CPUS)

	recorder_e = pool.apply_async(consolidate_results, (output_e,'.side_e.txt',))
	recorder_d = pool.apply_async(consolidate_results, (output_d,'.side_d.txt'))

	jobs = [pool.apply_async(attempt_meet_in_middle, (div, output_e, output_d)) for div in myList]

	for job in jobs:
		job.get()

	output_e.put('kill')
	output_d.put('kill')
	pool.close()
	pool.join()

	print('[Main] Libraries complete!')

	print('[Main] Cutting & Sorting...')

	os.system('cut -d ":" -f 1 .side_e.txt | sort > .side_e.txt.sorted')
	os.system('cut -d ":" -f 1 .side_d.txt | sort > .side_d.txt.sorted')

	# Locate common ct
	common_ps = Popen(['comm', '-12', '.side_e.txt.sorted', '.side_d.txt.sorted'], stdout=PIPE, stderr=PIPE)
	common = common_ps.communicate()[0].lstrip().strip()
	print('[Main] Common ct found: '+common)

	# Locate keys
	ps = Popen(('grep', common, '.side_e.txt'), stdout=PIPE)
	key1 = check_output(('cut', '-d', ':', '-f', '2'), stdin=ps.stdout).lstrip().strip()
	ps.wait()

	ps = Popen(('grep', common, '.side_d.txt'), stdout=PIPE)
	key2 = check_output(('cut', '-d', ':', '-f', '2'), stdin=ps.stdout).lstrip().strip()
	ps.wait()

	print('[Main] Keys: '+key1+","+key2)

	# Grab the flag
	key = pack('<I', int(key2))
	key = pad(key)
	cryptor = AES.new(key, AES.MODE_ECB)
	pt_1 = cryptor.decrypt(ct)

	key = pack('<I', int(key1))
	key = pad(key)
	cryptor = AES.new(key, AES.MODE_ECB)
	flag = cryptor.decrypt(pt_1)

	os.system('rm ./.side_*')

	print('[Main] All Done!')

	print(flag)

if __name__ == "__main__":
	main()
