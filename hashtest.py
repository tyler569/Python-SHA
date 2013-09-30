# Python_SHA
# Copyright (C) Tyler Philbrick; 2013
# Licensed GNU GENERAL PUBLIC LICENSE Version 2
# See LICENSE.txt for full license

import hashintf
import sys


def test():
	import hashlib
	tests = [
		'',
		' ',
		'x',
		'xxxxxxxxxxxxxxxxxxxxxxxxxxxx',
		'a billion dollars later - I had a poopiepie in my panypies',
		'The Great Big Fox Jumped Over the Hexadecimal Data: 0x57498156A21748194B4231'
	]

	
	for j in hashintf._valid_algorithms[:-2]:
		for i in tests:
			exec('x = hashlib.{}(i.encode()).hexdigest()'.format(j.lower()))
			exec('y = hashintf.hash("{}", i)'.format(j))
			#try:
			assert x == y
			#except AssertionError as e:
			print(j, ': ', i)
			print(x)
			print(y)
			#	sys.exit()
		print('{} all good'.format(j))
	print('All tests passed!!!!!!!')


def main():
	test()


if __name__ == '__main__':
	main()