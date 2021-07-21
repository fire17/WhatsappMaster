#Service.py
import time
import spotipy
import spotipy.util as util
from youtube_search import YoutubeSearch
from google_trans_new import google_translator

from bs4 import BeautifulSoup
from pprint import pprint as pp
import requests

import lxml, urllib
from threading import Thread

import os, requests, uuid, json, re
import requests
from youtube_title_parse import get_artist_title
from google_trans_new import google_translator
from bs4 import BeautifulSoup, UnicodeDammit, NavigableString
translator = google_translator()

from selenium.webdriver.common.keys import Keys
from selenium import webdriver

from googlesearch import search

translator = google_translator()

import traceback
import cv2
import numpy as np

import shazi
from geniusLyrics import *
# o = shazi.shazam("a.mp3")


class MusicService(object):
	id = "Music"
	name = "🔊 Music 🔊"
	welcome = "*Welcome to Music 🔊 Service!* \n\nSend us the name of a song to get *Youtube* and *Spotify* Links :)"+"\n*שלחו שם של שיר :)*"
	help = "send a message to get it back"
	imageurl = "https://i.imgur.com/lpjQPk5.jpg"
	shortDescription = "Just get your music"
	share = None

	examples = {"example1":{"text":"","thumbnail":None, "answer":"sweet child"}, "example2":{"text":"","thumbnail":None, "answer":"כחולת עינים"}}
	coms = ["Scraper"]


	def __init__(self,db, api):
		MusicService.share = self

		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! MusicService",MusicService.share)
		self.db = db
		self.api = api
		if "upcoming" not in self.db:
			self.db["upcoming"] = []
		if "users" not in self.db:
			self.db["users"] = {}

		self.spotify = None
		self.spotiAlive()

		self.commands = {"more":None,"עוד":None,"lyrics":None,"מילים":None,"danilator":None,"translation":None,"תרגום":None,"chords":None,"אקורדים":None, "other":None,"אחרים":None}
		self.activity = False

		self.prePath = ""
		on_heroku = False
		if 'ON_HEROKU' in os.environ:
			print("ENV ENV ENV ENV ENV ENV ENV ENV ENV ENV ENV ENV ")
			print("ENV ENV ENV       HEROKU        ENV ENV ENV ENV ")
			print("ENV ENV ENV ENV ENV ENV ENV ENV ENV ENV ENV ENV ")
			on_heroku = True
			self.prePath = "/app/"


	''' restarts spotify to keep it alive '''
	def spotiAliveAsync(self, data):
		while(True):
			try:
				token = spotipy.SpotifyClientCredentials(client_id ='d419f4fe1de143c0ab7561734322fbe2', client_secret='a5738d2f12a44336b74153cc96a1946e')
				cache_token = token.get_access_token()
				self.spotify = spotipy.Spotify(cache_token)
			except Exception as e:
				print()
				print("EEEEEEEEEEEEEE spotify init",e)
				print("EEEEEEEEEEEEEE spotify init",e)
				print("EEEEEEEEEEEEEE spotify init",e)
				print()
				print()
				traceback.print_exc()
			time.sleep(30*60)


	def spotiAlive(self):
		st = Thread(target = self.spotiAliveAsync, args = [None])
		st.start()

	def go(self):
		while(True):
			if self.activity:
				self.activity = False
				self.backup()
				time.sleep(60*3)
			# if "upcoming" not in self.db:
			# 	self.db["upcoming"] = []
			# if "users" not in self.db:
			# 	self.db["users"] = {}
			#
			# while len(self.db["upcoming"]) > 0:
			# 	item = self.db["upcoming"].pop(0)
			# 	origin, content = item
			# 	self.api.send(origin, content)
			# 	# self.api.backup(self.db)
			#
			# time.sleep(1)


	def artistInHebrew(self,q, s = 20, lang = None):
		# return search(q,stop = s)
		text = urllib.parse.quote_plus(q+" hebrew")
		url = 'https://google.com/search?q=' + text
		if lang is not None:
			url = url.replace(".com",lang)
		response = requests.get(url)
		soup = BeautifulSoup(response.text, 'lxml')
		res = soup.text
		if "hebrew:" in res.lower():
			artistHeb = " ".join(res.lower().split("hebrew: ")[1].split(" ")[:len(q.split(" "))])
			while not artistHeb[-1].isalpha():
				artistHeb = artistHeb[:-1]
			return artistHeb
		return q


# l = driver.find_element_by_id("link")
# l.send_keys(songURL+Keys.ENTER)

	def urlCheck(self, query):
		print("QQQQQQQQQQQQQQQQ",query)
		if query is "":
			return  render_template('base.html',title = u"\U0001F49A")
		urlChecks = ["http","youtu","spotify"]
		url = False
		for check in urlChecks:
			if check.lower() in query.lower():
				url = True
		print("START")
		processed_text = ""
		if url:
			print(query,"!!!!!!!!!!!!!!!!!!!")
			query = str(re.search("(?P<url>https?://[^\s]+)", query).group("url"))
			print(query,"!!!!!!!!!!!!!!!!!!!!")
			html = self.getHTML(query)
			try:
				if "spotify" in query:
					full = html.title.string
					full = full.split(', a song by ')
					full[1] = full[1].split(" ")[0].replace(","," ")
					title, artist = full
					title = str(re.sub(r" ?\([^)]+\)", "", title))
					artist = str(re.sub(r" ?\([^)]+\)", "", artist))
					processed_text = title +" "+artist
					print(processed_text)
				else:
					processed_text = "-".join(html.title.string.split("-")[:-1]).replace("/"," ")
			except Exception as e:
				print("EEEEEEEEEEEEEEEEEE: Processing Text ",e)
				processed_text = ""
				return query, None, None
				# return render_template('base.html')
			print("UUUUUUUUUUUUUUUUUUUUUU",processed_text)
			print("UUUUUUUUUUUUUUUUUUUUUU",processed_text)
			print("UUUUUUUUUUUUUUUUUUUUUU",processed_text)
		else:
			processed_text = query
		if processed_text == "":
			return " ", None, None
		return processed_text, None, None

	def getLTR(self, html):
		c = 0
		lyrics = []
		done = False
		for el in html.findAll("span", {"dir":"ltr"}):
			if c >= 2 and not done:
				if len(el.text) > 30:
					for line in el.text.split("\n"):
						lyrics.append(line)
				else:
					done = True
			c+=1
		return lyrics



	def searchGoogle(self, q, s = 5):
		res = []
		for r in self.google(q, s=s):
			res.append(r)
		return res


	def google(self, q, s = 20, lang = None):
		return search(q,stop = s)

	def getHTML(self, url):
		headers_Get = {
				'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0',
				'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
				'Accept-Language': 'en-US,en;q=0.5',
				'Accept-Encoding': 'gzip, deflate',
				'DNT': '1',
				'Connection': 'keep-alive',
				'Upgrade-Insecure-Requests': '1'
			}
		searchPage = requests.get(url, headers=headers_Get)
		html = BeautifulSoup(searchPage.text,'html.parser')
		return html


	# def downloadImage(self,url= 'https://www.tab4u.com/tabs/songs/68069_יסמין_מועלם_-_מסיבה.html',siteData, savePath = "screenshot1.png"):
	def downloadImage(self,url,siteData, savePath = "screenshot1.png"):
		# driver = webdriver.Chrome()
		site, finElement = siteData
		savePath = self.prePath + savePath
		songURL = url
		st = time.time()
		chrome_options = webdriver.ChromeOptions()
		chrome_options.add_argument('--headless')
		chrome_options.add_argument('--start-maximized')
		driver = webdriver.Chrome(chrome_options=chrome_options)
		url = 'https://web-capture.net/'
		print("TTTTTTTTTTTTT", time.time()-st)
		# input()
		# st = time.time()
		fromCap = False
		if fromCap:
			driver.get(url)
			print("TTTTTTTTTTTTT", time.time()-st)
			l = driver.find_element_by_id("link")
			l.send_keys(Keys.SHIFT+Keys.HOME)
			l.send_keys(Keys.BACKSPACE)
			l.send_keys(songURL+Keys.ENTER)
			go = "https://web-capture.net/picture.php?pic_index=1&presentation_method=inline"
			driver.get(go)
			ele = i = driver.find_element_by_tag_name("img")
			ele.click()
		else:
			# go = "https://web-capture.net/picture.php?pic_index=1&presentation_method=inline"
			driver.get(songURL)
			# ele = i = driver.find_element_by_tag_name("img")
			ele = element = i = el = driver.find_element_by_id(finElement)
			print("TTTTTTTTTTTTT", time.time()-st)
			# ele.click()
		total_height = ele.size["height"]+1000
		print("total_height",total_height)
		lowImage = False
		if lowImage:
			total_height = 2000
		driver.set_window_size(1920, total_height)      #the trick
		# time.sleep(2)
		driver.save_screenshot(savePath)
		print("TTTTTTTTTTTTT", time.time()-st)
		driver.quit()
		image = cv2.imread(savePath)
		templateStart = cv2.imread(self.prePath+"websites/"+site+"/start.png")
		templateStart2 = cv2.imread(self.prePath+"websites/"+site+"/start2.png")
		templateFin = cv2.imread(self.prePath+"websites/"+site+"/finish.png")
		# templateFin  = cv2.cvtColor(cv2.imread("taboola.png"), cv2.COLOR_BGR2GRAY)
		# templateStart  = cv2.cvtColor(cv2.imread("scroll.png"), cv2.COLOR_BGR2GRAY)
		print(image.shape)
		print(templateStart.shape)
		resultF = cv2.matchTemplate(image,templateFin,cv2.TM_CCOEFF_NORMED)
		finY, finX = np.unravel_index(resultF.argmax(),resultF.shape)
		resultS = cv2.matchTemplate(image,templateStart2,cv2.TM_CCOEFF_NORMED)
		startY,startX, = np.unravel_index(resultS.argmax(),resultS.shape)
		# crop_img = image[startY:finY, startX+200:-450]
		print(startY, finY, startX+templateStart.shape[1],finX+templateFin.shape[1]+5)
		# crop_img = image[startY-138-templateStart.shape[0]:finY, startX:finX+templateFin.shape[1]+5]
		if startY > finY:
			resultS2 = cv2.matchTemplate(image,templateStart,cv2.TM_CCOEFF_NORMED)
			startY,startX, = np.unravel_index(resultS2.argmax(),resultS2.shape)
			# crop_img = image[startY:finY, startX+200:-450]
		if startY > finY:
			startY = 0
		crop_img = image[startY:finY, startX+templateStart.shape[1]:finX+templateFin.shape[1]+5]
		filename = self.prePath +"websites/"+site+'/Celement.jpg'
		cv2.imwrite(filename, crop_img)
		print("TTTTTTTTTTTTT", time.time()-st)
		# return [filename]
		buffer = 15
		divs = 1
		fns = []
		height = finY - startY
		if height > 2400:
			divs = 4
		for i in range(divs):

			min = startY + int(height/divs)*(i) - buffer
			if min < 0:
				min = 0
			max = startY + int(height/divs)*(i+1) + buffer
			if max > finY:
				max = finY-2
			nf = filename.split('.')[0]+str(i)+"."+filename.split('.')[1]
			fns.append(nf)
			print("NNNNNNN",finY,nf, min,max)
			cv2.imwrite(nf, image[min:max, startX+templateStart.shape[1]:finX+templateFin.shape[1]+5])
		# Using cv2.imwrite() method
		# Saving the image
		# cv2.imwrite(filename, crop_img)
		print("TTTTTTTTTTTTT", time.time()-st)
		return fns


#
#
#
#
# 	driver.get(songURL)
# 	# ele = i = driver.find_element_by_tag_name("img")
# 	ele = element = i = el = driver.find_element_by_id("songContentTPL")
# 	# element = html.find_element_by_id()
# 	# element = driver.find_element_by_id("hplogo");
# 	# element = el
# 	location = element.location;
# 	size = element.size;
# 	driver.quit()
# 	# driver.save_screenshot("pageImage.png");
# 	# crop image
# 	x = location['x'];
# 	y = location['y'];
# 	width = location['x']+size['width'];
# 	height = location['y']+size['height'];
# 	im = Image.open(savePath)
# 	im = im.crop((int(x+200), int(y), int(width), int(height)))
# 	im.save('element.png')
# 	print("TTTTTTTTTTTTT", time.time()-st)
# 	html = getHTML("",songURL)
# 	return html, driver,i,total_height
#
#
# html, driver,i,total_height = res = downloadImage("")
#
# image = cv2.imread("scrx.png")
# templateFin = cv2.imread("taboola.png")
# templateStart = cv2.imread("scroll.png")
# resultS = cv2.matchTemplate(image,templateStart,cv2.TM_CCOEFF_NORMED)
# resultF = cv2.matchTemplate(image,templateFin,cv2.TM_CCOEFF_NORMED)
#
# startY,startX, = np.unravel_index(resultS.argmax(),result.shape)
# finY, finX = np.unravel_index(resultF.argmax(),result.shape)
# crop_img = image[startY:finY, startX+200:-450]
# print(startY)
# crop_img = image[startY-138-templateStart.shape[0]:finY, startX:finX+templateFin.shape[1]+5]
# filename = 'Celement.png'
# # Using cv2.imwrite() method
# # Saving the image
# cv2.imwrite(filename, crop_img)


	def getLyrics(self, title):
		# return lyricwikia.get_lyrics('Led Zeppelin', 'Stairway to heaven')
		# search("")
		# print("title",title)
		url='https://www.google.com/search?q='
		# s=input('Enter the song to find its lyrics: ')
		s = '\"'+title+'\"'
		#calculating time taken in searching lyrics
		# a = datetime.datetime.now()
		for i in s:
			if i==' ':
				url+='+'
			else:
				url+=i
		url+='+lyrics'
		html = self.getHTML(url)
		# print("\n#####",html,"\n###########")
		song_info = []
		song_title = []
		for paper in html.findAll("div",class_="auw0zb"):
			for desc in paper.descendants:
				print("DDDDDDDD",desc)
			info = [desc.strip() for desc in paper.descendants if type(desc) == NavigableString]
			for i in info:
				song_title.append(i)
		print("\n#####333333",song_title,"\n###########")
		if len(song_title) > 1:
			songtitle = song_title[1].split(" lyrics ©")[0]
			song_info.append(songtitle)
		else:
			try:
				song_info.append(html.findAll("span",{"class":"BNeawe tAd8D AP7Wnd"})[0].text)
			except:
				print("error getting artist")
		artists = []
		# for paper in html.findAll("div",class_="wwUB2c PZPZlf"):
		for paper in html.findAll("div",class_="wx62f PZPZlf x7XAkb"):
			for desc in paper.descendants:
				print("DDDDDDDD",desc)
			info = [desc.strip() for desc in paper.descendants if type(desc) == NavigableString]
			for i in info:
				artists.append(i)
		print("\n#####",artists,"\n###########")
		if len(artists) > 0:
			artist = artists[0].replace("Song by ","")
			song_info.append(artist)
		else:
			try:
				song_info.append(html.findAll("span",{"class":"BNeawe s3v9rd AP7Wnd"})[1].text)
			except:
				print("error getting artist")
		if len(song_info) < 2:
			print("wwwwwwwwwwww",song_info)
			song_info = []
			for paper in html.findAll("div",class_="SPZz6b"):
				for desc in paper.descendants:
					print("DDDDDDDD",desc)
				info = [desc.strip() for desc in paper.descendants if type(desc) == NavigableString]
				for i in info:
					song_info.append(i)
		lyrics=html.find_all("span", jsname="YS01Ge")
		new_method = False
		if lyrics==[]:
			print('Couldn\'t get lyrics')
			lyrics = self.getLTR(html)
			new_method = True
		if lyrics==[]:
			print('Couldn\'t get lyrics')
		else:
			nlyr = ""
			nl = ["; ","\n"]
			c = 0
			if not new_method:
				for i in lyrics:
					# print(i.get_text())
						nlyr += i.get_text() + nl[c%2]
						c+=1
			else:
				for i in lyrics:
				# print(i.get_text())
					nlyr += i + nl[c%2]
					c+=1
			return nlyr, song_info


	def chunks(self, lst, n):
		"""Yield successive n-sized chunks from lst."""
		for i in range(0, len(lst), n):
			yield lst[i:i + n]

	def danilator(self, item, withTranslations = False, lang_tgt="he", lyrics = None):
		if item == "":
			return "", ["",""]
			# item = input('Enter the song to find its lyricsxx: ')
		res = None
		maxTries = 4
		mc = 0
		song_info = None
		if lyrics is None:
			lyricsText, song_info = "sorry, lyrics not found, try again soon ",["Could not find lyrics",item]
			while res is None and mc <= maxTries:
				# try:
				target = item
				print("ITEM:"+target)
				artist_title = get_artist_title(target)
				if artist_title is not None:
					print("@@@@@@@@@@@@@@@@@@@@",artist_title)
					artist, title = artist_title
					if mc==1:
						target = title+" " + artist
						item = item.replace("&"," and ")
					if mc==2:
						target = title+" " + artist.split(" ")[0]
					if mc==3:
						target = title
				else:
					print("!!!!!!!!!!!!!!!!!!!!!!!!")
					print("!!!!!!!!!!!!!!!!!!!!!!!!")
					print("!!!!!!!!!!!!!!!!!!!!!!!!")
				print("TTTTTTTTTTTTTTTTT")
				print(target)
				print("TTTTTTTTTTTTTTTTT")
				# except:
				# 	print("E: could not parse artist and title")
				# res = self.getLyrics(target)
				res = None
				gtry = 0
				maxtries = 2
				while not res and gtry < maxtries:
					if gtry >= 2:
						time.sleep(gtry)
					try:
						res = GeniusSearchLyrics(target)
					except:
						traceback.print_exc()

					gtry +=1

				mc+=1
				if res is not None and len(res) > 1:
					gtitle, gartist, lyricsText = res
					# lyricsText, song_info = res
					song_info = [gtitle, gartist]
			chars = [["-"," "],["(",""],[")",""],["~",""],["\r",""]]
			for c in chars:
				lyricsText = lyricsText.replace(c[0],c[1])
			# .replace().replace("(","").replace(")","")
			lyrics = []
			for l in lyricsText.split("\n"):
				lyrics.append(l)
			# body = [{
		# 	'text' : lyricsText
		# }]
		else:
			lyricsText = "\n".join(lyrics).replace("\r","")

		translated = []
		if withTranslations:
			n = 0
			parts = []
			print(lyricsText)
			print(type(lyricsText), len(lyricsText),len(lyricsText.split("\n")))
			maxChunks = 50
			for chunk in self.chunks(lyricsText.split("\n"), maxChunks):
				chunkT = "~".join(chunk)
				print("!!!!!!!!!!!!","\n",chunkT)
				res = translator.translate(str(chunkT),lang_tgt = lang_tgt)
				print("$$$$$$$$$$$$$$$$$$$$$")
				print(res)
				parts.append(res+"\n")
			# time.sleep(1)
				# n+=1
			# res = translator.translate(lyricsText,lang_tgt="he")
			print("########################@@@")
			print(parts)
			# translated = res.__dict__()["text"]
			translated = ("\n".join(("".join(parts)).split("~"))).split("\n")
			print("############################")
			print(translated)
			print("XXXXXXXXXXXXXXXXXXXXXXXXXXX")
		fullL = []
		# fullt = "<h1>"+item+"</h1>"
		for c in range(len(lyrics)):
			fullL.append(lyrics[c])
			if c < len(translated):
				fullL.append(translated[c])
				fullL.append("")
				# fullL.append("")
			# fullt += "<pre>"+lyrics[c] + "</pre>"
			# fullt += "<pre>"+translated[c][::-1] + "</pre>"
			# print(lyrics[c])
			# print(translated[c])
			print("")
		print(" @ @ @ @ @ @  @")
		print(fullL)
		return "\n".join(fullL), song_info

	def process(self, info):
		origin, user, content, quoted = None, None, None, None
		if "origin" in info:
			origin = info["origin"]
		if "user" in info:
			user = info["user"]
		if "content" in info:
			content = info["content"]
		if "quotedMsg" in info:
			quoted = info["quotedMsg"]


		if "users" not in self.db:
			self.db["users"] = {}

		if origin not in self.db["users"] or "dict" not in str(type(self.db["users"][origin])):
			self.db["users"][origin] = {"history":{}}

		# print("SELF>DB")
		# print(self.db)
		print("ORIGIN")
		print(self.db["users"][origin])
		if "settings" not in self.db["users"][origin]:
			self.db["users"][origin]["settings"] = {"defaults":{"more":True,"lyrics":False,"danilator":False,"chords":False}}


		content = content.replace("+"," ")
		hasCMD = False
		sent = False
		if origin.split("/")[0] in self.coms:
			hasCMD = True
			lastOrigin = "/".join(origin.split("/")[1:])
			add = ""
			if len(lastOrigin.split("/")) > 1:
				id = lastOrigin.split("/")[1]
				history = self.db["users"][lastOrigin.split("/")[0]]["history"]
				if len(history) >= int(id)+1:
					song = history[id]
					if song is not None:
						add = song["search"]
						if "title" in song:
							add = song["title"]
						if "artist" in song:
							add += " " + song["artist"]
						add +":\n"
				if "danilator" in origin:
					print("@@@@@@@@@@@@@@@")
					print("@@@@@@@@@@@@@@@")
					print("@@@@@@@@@@@@@@@")
					print("@@@@@@@@@@@@@@@")
					print("@@@@@@@@@@@@@@@")
					print("@@@@@@@@@@@@@@@",content)
					targetLanguage = "en"
					target = origin.split("danilator")[1]
					if len(target.split("/")) > 1:
						targetLanguage = target.split("/")[1]

					nlyr = ""
					nl = ["; ","\n"]
					c = 0
					for i in content.split("\n"):
						# print(i.get_text())
							nlyr += i + nl[c%2]
							c+=1

					lyrics = []
					for l in nlyr.split("\n"):
						if len(l) > 0:
							print("@@@:"+l)
							lyrics.append(l)
					# lyrics = content
					content, _ = self.danilator(song["search"],withTranslations=True,lang_tgt=targetLanguage,lyrics=lyrics)

					# cleanlyrics = []
					# for l in content.split("\n"):
					# 	if len(l) > 0:
					# 		print("@@@:"+l)
					# 		cleanlyrics.append(l)
					# content = "\n".join(cleanlyrics)
					print("###########")
					print("###########")
					print("###########")
					print("###########")
					print("###########",content)
					sent = True
					self.api.send(lastOrigin.split("/")[0], add+"\n"+content)

			if not sent:
				self.api.send(lastOrigin.split("/")[0], add+"\n"+content)
		else:

			if origin not in self.db["users"] or "history" not in self.db["users"][origin]:
				self.db["users"][origin] = {"history":{}}

		history = self.db["users"][origin]["history"]

			# self.api.send(origin, "ECHO |"+content+"|")

		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print("::::::::::::::::::::::::::::::::::::::::::::::::::::::")
		print(content)
		print()
		print()
		if content.split(" ")[0].lower() in self.commands:
			# cmdd = content.split(" ")[0]
			lastID = None
			if len(history) >= 1:
				lastID = str(len(history)-1)

			if quoted and "body" in quoted:
				if "*" in quoted["body"]:
					find = quoted["body"].split("*")[1].lower()
					foundID = None
					print("FINDING",find)
					for h in history:
						print(h,history[h])
						for k in history[h]:
							if history[h][k].lower() in find or find in history[h][k].lower() or history[h][k].lower() in find.split("-")[0] or find.split("-")[0] in history[h][k].lower() or history[h][k].lower() in find.split(" ")[0] or find.split(" ")[0] in history[h][k].lower():
								foundID = h
						#
						# if "search" in history[h] and find in history[h]["search"].lower() or ("title" in history[h] and find in history[h]["title"].lower()):
						# elif "search" in history[h] and find.split(" ")[0] in history[h]["search".lower()	] or ("title" in history[h] and find.split(" ")[0] in history[h]["title"].lower()):
						# 	foundID = h

					if foundID:
						print("GGGGGGGGGGOOOOOTTTTTTTTTT SSSSOOOONNNGGGGG IDDDD FROM REPLYYYYYY",foundID)
						lastID = foundID
			''' before first song '''
			if lastID is None:
				pass
			else:
				if len(content.split(" "))>1 and content.split(" ")[0].lower() in self.db["users"][origin]["settings"]["defaults"]:
					second = content.split(" ")[1]
					d = {"on":True,"off":False, "toggle": not self.db["users"][origin]["settings"]["defaults"][content.split(" ")[0].lower()]}
					if second.lower() in d:
						op = d[second.lower()]
						self.db["users"][origin]["settings"]["defaults"][content.split(" ")[0].lower()] = op

						return 	self.api.send(origin, "Changed Default Settings: "+content.split(" ")[0]+" is "+second, thumnail = None)



				content = ":"+lastID+":"+content


		if ":" == content[0]:
			if len(content.split(":")) > 2 and len(content.split(":")[2])>0:

				hasCMD = True
				l = content.split(":")
				id = l[1]
				try:
					cmd = l[2].lower()
					print("CMD",cmd,"id",id,"HIST",history)
					if len(history) >= int(id)+1:
						song = history[id]
						title = ""
						artist = ""
						if song is not None:
							if "title" in song:
								title = song["title"]
							if "artist" in song:
								artist = song["artist"]

						if title is "":
							title = song["search"]

						print("TTTTTTTTTTTTTTTT",title)

						if cmd == "more" or cmd == "עוד":
							sendLinks = ""
							link = song["link"]

							sendLinks += "👯‍ *Covers* and *Other Artists*\n"+link+"other"+"\n\n"

							sendLinks += "📖 *Song Lyrics*:\n"+link+"lyrics"+"\n"
							sendLinks += "🌐 *Lyrics Translation*:\n"+link+"danilator"+"\n"
							sendLinks += "🎸 *Get Chords*:\n"+link+"chords"+"\n"
							#
							# answer = ":lyrics:"+str(songID)
							# link = self.api.genLink(origin, answer, newLink = str(songID)+"-lyrics")
							#
							# answer = ":danilator:"+str(songID)
							# link = self.api.genLink(origin, answer, newLink = str(songID)+"-danilator")
							# sendLinks += "Lyric Translation: "+link+"\n"
							#
							# answer = ":chords:"+str(songID)
							# link = self.api.genLink(origin, answer, newLink = str(songID)+"-chords")
							# sendLinks += "Get Chords: "+link+"\n"
							# time.sleep(1.5)
							self.api.send(origin, sendLinks, thumnail = None)
						if cmd == "other" or "אחר" in cmd:
							# self.api.send(origin, "FINDING OTHER ARTIST FOR "+title+" "+artist)
							newArtists = []
							if "artist" in song:
								results = self.spotify.search(song["search"])
								if len(results) > 0 and "tracks" in results and "items" in results["tracks"]:
									for res in results['tracks']['items']:
										# link = res['external_urls']['spotify']
										# title = res["name"]
										newArtist = res["album"]["artists"][0]["name"]
										if song["artist"].lower() == newArtist.lower():
											pass
										else:
											newArtists.append(res["name"]+"~"+newArtist)
										# image = res["album"]["images"][1]['url']
							title = song["title"]
							sendArtist = ""

							baselink = song["link"].split(":")[0]


							link = baselink+song["search"].replace(" ","+")+"+Karaoke"
							sendArtist +=  "🎤 *"+title+" - Kareoke* : \n"
							# sendArtist +=   *Acoustic Version* : \n"
							sendArtist += link+"\n\n"

							link = baselink+song["search"].replace(" ","+")+"+Acoustic+Cover"
							sendArtist +=  "🎺 *Acoustic Version* : \n"
							sendArtist += link+"\n\n"
							for nA in newArtists:

								tit, art = nA.split("~")
								artist_title = get_artist_title(nA.replace("~"," "))
								if artist_title is not None:
									print("@@@@@@@@@@@@@@@@@@@@",artist_title)
									art, tit = artist_title

								link = baselink+tit.replace(" ","+")+"+"+art.replace(" ","+")
								sendArtist +=  "*"+tit+" - "+art+"* : \n"
								sendArtist += link+"\n"

							self.api.send(origin, "*Covers* and *Other Artists*:\n\n"+sendArtist)

						if cmd == "lyrics" or cmd == "מילים":
							print("LLLLLLLLLLLLLLLLLLLLLLLLLLL")
							print("LLLLLLLLLLLLLLLLLLLLLLLLLLL")
							print("LLLLLLLLLLLLLLLLLLLLLLLLLLL")
							print("LLLLLLLLLLLLLLLLLLLLLLLLLLL")

							if song["language"] is "hebrew":
								# try:
								if "artist" in song and translator.detect(song["artist"])[1] is not "hebrew":
									artist = self.artistInHebrew(artist)
										# artist = song["artist"] = translator.translate(song["artist"],lang_tgt="he")
								# 	if "title" in song and translator.detect(song["title"])[1] is not "hebrew":
								# 		title = song["title"] = translator.translate(song["title"],lang_tgt="he")
								# except :
								# 	traceback.print_exc()
								self.api.send(origin, "*Searching for lyrics:* \n "+title+" "+artist)
								print("LLLLLLLLLLLLLLLLLLLLLLLLLLL")
								self.api.send("Scraper"+"/"+origin+"/"+id, ":shironet:"+title+" "+artist+" shironet")
								# self.api.send("Scraper"+"/"+origin, ":shironet:"+song["search"]+" shironet")
							else:

								# fullT, songInfo = self.danilator(title+" "+artist)
								fullT = "Could not load lyrics"
								glyrics = None
								try:
									gtitle, gartist, glyrics = GeniusSearchLyrics(title+" "+artist)
								except:
									time.sleep(2)
									try:
										gtitle, gartist, glyrics = GeniusSearchLyrics(title+" "+artist)
									except:
										try:
											gtitle, gartist, glyrics = GeniusSearchLyrics(title+" "+artist)
										except:
											traceback.print_exc()
								if glyrics:
									fullT = glyrics

								header = "*"+title
								if artist is not "":
									header += " - "+artist+"*\n\n"
								else:
									header += "*\n\n"

								# print("songInfo", songInfo)
								# print("songInfo", songInfo)
								# print("songInfo", songInfo)
								# print("songInfo", songInfo)
								# print("songInfo", songInfo)
								self.api.send(origin, header+fullT)
								# self.api.send("Scraper"+"/"+origin, ":googlelyrics:"+title+" "+artist+" lyrics")

						if cmd == "chords" or cmd == "אקורדים":
							sites = [["tab4u","taboola-below-article-thumbnails"],["e-chords","request"]]
							self.api.send(origin, "*Searching Chords for:* \n "+title+" "+artist)
							q = title+" "+" Chords"
							searches = self.searchGoogle(q,s=20)
							foundURL = None
							foundSite = None
							for s in searches:
								print("SSSSSSS",s)
								for k in sites:

									if k[0] in s:
										print("found",k)
										foundURL = s
										foundSite = k
									print("lastk",k)
							if foundURL:
								print("UUUUUUUUUUUUUUUUUUUUUU",foundURL)
								print("UUUUUUUUUUUUUUUUUUUUUU",foundURL)
								print("UUUUUUUUUUUUUUUUUUUUUU",foundURL)
								fns = self.downloadImage(url = foundURL, siteData = foundSite)
								for dlp in fns:
									print("FFFFFFFFFFFFFFFFFFFFFFFFFFF",dlp)
									self.api.send(origin, "image/"+dlp)
									time.sleep(0.8)





						if cmd.lower() in ["danilator","תרגום","translation","translations","translate"]:
							print("DDDDDDDDDDDDDDDDDDDDD")
							print("DDDDDDDDDDDDDDDDDDDDD")
							print("DDDDDDDDDDDDDDDDDDDDD",song)

							if song["language"] is "hebrew":
								self.api.send("Scraper"+"/"+origin+"/"+id+"/danilator/en", ":shironet:"+title+" "+artist+" shironet")
							elif song["language"] is "english" or True:
								fullT, songInfo = self.danilator(title+" "+artist, withTranslations=True)
								header = "*"+title
								if artist is not "":
									header += " - "+artist+"*\n\n"
								else:
									header += "*\n\n"

								print("songInfo", songInfo)
								print("songInfo", songInfo)
								print("songInfo", songInfo)
								print("songInfo", songInfo)
								print("songInfo", songInfo)
								self.api.send(origin, header+fullT)


					# self.api.send(origin, "FUCK YEA "+content)
				except :
					traceback.print_exc()

		if not hasCMD:


			songID = str(len(history))
			lang = "english"

			check, uTitle, uArtist = self.urlCheck(content)
			if check != content:
				try:
					print("FROM URL",check)
					# get title artist
					res = translator.detect(check)
					if res is not None and len(res) > 1:
						lang = res[1]
				except:
					traceback.print_exc()
			else:
				try:
					res = translator.detect(content)
					if res is not None and len(res) > 1:
						lang = res[1]
				except:
					traceback.print_exc()

			link = self.api.genLink(origin) + ":"+str(songID)+":"
			history[songID] = {"search":content, "language":lang, "link":link}




			# if user not in self.db["users"]:
			# 	self.db["users"][user] = user
			# 	self.api.send(origin, "WELCOME "+user)
			# 	self.backup()

			# self.db["upcoming"].append([origin, content])

			# query = "sweet child"
			thumnail = None
			sendBack = "Sorry we could not find your song on Spotify for some reason.\n\n"
			found = False
			image = self.imageurl
			try:
				results = self.spotify.search(content)
				print("# # # # # # # # ")
				# pp(results)
				# print("# # # # # # # # ")
				if len(results) > 0:
					res = results['tracks']['items'][0]
					slink = res['external_urls']['spotify']
					title = res["name"]
					artist = res["album"]["artists"][0]["name"]
					image = res["album"]["images"][1]['url']
					year = res["album"]["release_date"].split("-")[0]
					desc = artist
					if res["type"] == "track":
						desc += " • Song"
					desc += " • "+year
					thumnail = {"imageurl":image,"title":title,"desc":desc,"link":slink}
					found = True
			except Exception as e:
				print("COULD NOT FIND SONG ON SPOTIFY", e)

			search = content
			if found:

				sendBack = "Spotify: *"+title+" - "+artist+"*\n"
				sendBack += slink+"\n\n"
				search = title+" "+artist
				history[songID]["title"] = title
				history[songID]["artist"] = artist

			linkDefault = "spotify"
			ytres = None
			try:
				ytres = YoutubeSearch(search, max_results=1).to_dict()
			except :
				traceback.print_exc()

			if ytres is not None and len(ytres) == 1:
				try:
					print("# # # # # # # # ")
					print("# # # # # # # # ")
					print("# # # # # # # # ")
					print("# # # # # # # # ")
					print("# # # # # # # # ")
					print(ytres[0])
					vidID = ytres[0]['url_suffix']
					title = ytres[0]['title']
					ylink = "https://youtu.be"+vidID
					desc = ytres[0]['channel']
					image = ytres[0]["thumbnails"][0]
					if vidID is not None and len(vidID) > 0:

						artist_title = get_artist_title(title)
						if artist_title is not None:
							print("@@@@@@@@@@@@@@@@@@@@",artist_title)
							art, tit = artist_title
							if "title" not in history[songID]:
								history[songID]["title"] = tit
							if "artist" not in history[songID]:
								history[songID]["artist"] = art

						sendBack+="Youtube: *"+title+"*"+"\n"+ylink

					''' thumnail for youtube '''
					if not found or linkDefault is "youtube" or False:

						thumnail = {"imageurl":image,"title":title,"desc":desc,"link":ylink}

				except Exception as e:
					print("COULD NOT FIND SONG ON YOUTUBE", e)

			# self.api.send(origin, sendBack, thumnail = thumnail)


			sendLinks = ""
			answer = str(songID)

			sendLinks += "https://"+link+"more"


			#
			# sendLinks = ""
			# answer = ":other:"+str(songID)
			# link = self.api.genLink(origin, answer, newLink = str(songID)+"-other")
			# sendLinks += "Looking for different Artist?:\n"+link+"\n\n"
			#
			# answer = ":lyrics:"+str(songID)
			# link = self.api.genLink(origin, answer, newLink = str(songID)+"-lyrics")
			# sendLinks += "Get Chords: "+link+"\n"
			#
			# answer = ":danilator:"+str(songID)
			# link = self.api.genLink(origin, answer, newLink = str(songID)+"-danilator")
			# sendLinks += "Lyric Translation: "+link+"\n"
			#
			# answer = ":chords:"+str(songID)
			# link = self.api.genLink(origin, answer, newLink = str(songID)+"-chords")
			# sendLinks += "Get Chords: "+link+"\n"
			tit = search
			if "title" in history[songID]:
				tit = str(history[songID]["title"])
			seeMore = "See More Options ("+tit+")"
			self.api.send(origin, sendBack, thumnail = thumnail)
			time.sleep(1.2)

			for cmd in self.db["users"][origin]["settings"]["defaults"]:
				if self.db["users"][origin]["settings"]["defaults"][cmd]:
					self.process({"origin":origin,"user":user,"content":":"+songID+":"+cmd})

			if False:
				self.api.send(origin, "🍀 "+sendLinks, thumnail = {"imageurl":None,"title":seeMore,"desc":"Other Artists, Covers, Lyrics and Chords","link":"https://"+link+":more"})


			# time.sleep(1.5)

			# self.api.send(origin, sendLinks, thumnail = {"imageurl":image,"title":"seeMore","desc":"Other Artists, Covers","link":link+":more"}

			self.activity = True

	def backup(self):
		self.api.backup(self.db)

	def updateDB(self, db):
		self.db = db
		# self.db = User.jsonUsersToUsers(db)

	def welcomeUser(self, origin):
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		if "users" not in self.db:
			self.db["users"] = {}
		if origin not in self.db["users"]:
			self.db["users"][origin] = {}
			self.backup()
