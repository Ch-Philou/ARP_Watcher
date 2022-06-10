#!/usr/bin/env python3
# coding: utf-8
#mix between
#  http://sametmax.com/ecrire-des-logs-en-python/
#  https://gist.github.com/KurtJacobson/c87425ad8db411c73c6359933e5db9f9

import logging
import os
import datetime
 
from logging.handlers import RotatingFileHandler
from logging import Formatter
from copy import copy

MAPPING = {
	'DEBUG'   : 37, # white
	'INFO'	: 36, # cyan
	'WARNING' : 33, # yellow
	'ERROR'   : 31, # red
	'CRITICAL': 41, # white on red bg
}

PREFIX = '\033['
SUFFIX = '\033[0m'

class ColoredFormatter(Formatter):

	def __init__(self, patern):
		Formatter.__init__(self, patern)

	def format(self, record):
		colored_record = copy(record)
		#Coloring Level
		levelname = colored_record.levelname
		seq = MAPPING.get(levelname, 37) # default white
		colored_levelname = ('{0}{1}m{2}{3}').format(PREFIX, seq, levelname, SUFFIX)
		colored_record.levelname = colored_levelname

		#Coloring message
		message = colored_record.msg
		seq = MAPPING.get(levelname, 37) # default white
		colored_message = ('{0}{1}m{2}{3}').format(PREFIX, seq, message, SUFFIX)
		colored_record.msg = colored_message

		return Formatter.format(self, colored_record)


def Create_Log(
		Filename='activity.log',
		FileFormat='%(asctime)s ; %(funcName)s ; %(levelname)s ; %(message)s',
		StdOutFormat='%(asctime)s ; %(funcName)s (l %(lineno)s) ; %(levelname)s ; %(message)s',
		File_level=logging.DEBUG,
		Bash_Level=logging.DEBUG):
	# création de l'objet logger qui va nous servir à écrire dans les logs
	logger = logging.getLogger()
	# on met le niveau du logger à DEBUG, comme ça il écrit tout
	logger.setLevel(logging.DEBUG)
	 
	# création d'un formateur qui va ajouter le temps, le niveau
	# de chaque message quand on écrira un message dans le log

	
	
	Fileformatter = Formatter(FileFormat)
	Bashformatter = ColoredFormatter(StdOutFormat)
	
	
	# création d'un handler qui va rediriger une écriture du log vers
	# un fichier en mode 'append', avec 1 backup et une taille max de 1Mo
	file_handler = RotatingFileHandler(Filename, 'a', 1000000, 1)
	# on lui met le niveau sur DEBUG, on lui dit qu'il doit utiliser le formateur
	# créé précédement et on ajoute ce handler au logger
	file_handler.setLevel(File_level)
	file_handler.setFormatter(Fileformatter)
	logger.addHandler(file_handler)
	 
	# création d'un second handler qui va rediriger chaque écriture de log
	# sur la console
	steam_handler = logging.StreamHandler()
	steam_handler.setLevel(Bash_Level)
	steam_handler.setFormatter(Bashformatter)
	logger.addHandler(steam_handler)
	 
	# Après 3 heures, on peut enfin logguer
	# Il est temps de spammer votre code avec des logs partout :
	logger.info('Log Instanciation')
	return logger
	#logger.(info|warn|debug|error|critical).

def ClassicalLogger(RootFolder,ScriptName,verbosity):
	log_path="."
	returned_logger =None
	
	if os.path.isdir(RootFolder+os.sep+"Logs"):
		log_path=RootFolder+os.sep+"Logs"+os.sep+"Exec_"+ScriptName+"_"+datetime.datetime.now().strftime("%Y-%m-%d")+".log"
	else:
		log_path=RootFolder+os.sep+"Exec_"+ScriptName+"_"+datetime.datetime.now().strftime("%Y-%m-%d")+".log"
	
	if verbosity==5:
		returned_logger=Create_Log(
			log_path,
			FileFormat		=	'%(asctime)s ; %(filename)s (l %(lineno)s) ; %(funcName)s ; %(levelname)s ; %(message)s',
			StdOutFormat	=	'%(asctime)s ; %(filename)s (l %(lineno)s) ; %(funcName)s ; %(levelname)s ; %(message)s',
			File_level		=	logging.DEBUG,
			Bash_Level		=	logging.DEBUG)
	
	elif verbosity==4:
		returned_logger=Create_Log(
			log_path,
			FileFormat		=	'%(asctime)s ; %(funcName)s ; %(levelname)s ; %(message)s',
			StdOutFormat	=	'%(asctime)s ; %(funcName)s ; %(levelname)s ; %(message)s',
			File_level		=	logging.DEBUG,
			Bash_Level		=	logging.DEBUG)
	elif verbosity==3:
		returned_logger=Create_Log(
			log_path,
			FileFormat		=	'%(asctime)s ; %(funcName)s ; %(levelname)s ; %(message)s',
			StdOutFormat	=	'%(asctime)s ; %(funcName)s ; %(levelname)s ; %(message)s',
			File_level		=	logging.INFO,
			Bash_Level		=	logging.INFO)
	elif verbosity==2:
		returned_logger=Create_Log(
			log_path,
			FileFormat		=	'%(asctime)s ; %(funcName)s ; %(levelname)s ; %(message)s',
			StdOutFormat	=	'%(asctime)s ; %(levelname)s ; %(message)s',
			File_level		=	logging.INFO,
			Bash_Level		=	logging.INFO)
	elif verbosity==1:
		returned_logger=Create_Log(
			log_path,
			FileFormat		=	'%(asctime)s ; %(levelname)s ; %(message)s',
			StdOutFormat	=	'%(asctime)s ; %(levelname)s ; %(message)s',
			File_level		=	logging.INFO,
			Bash_Level		=	logging.INFO)
	else:
		returned_logger=Create_Log(
			log_path,
			FileFormat		=	'%(asctime)s ; %(levelname)s ; %(message)s',
			StdOutFormat	=	'%(asctime)s ; %(levelname)s ; %(message)s',
			File_level		=	logging.WARNING,
			Bash_Level		=	logging.INFO)
	
	returned_logger.info("Log at: "+str(log_path))

	return returned_logger