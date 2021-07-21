#Service.py
import time
import yfinance as yf
from datetime import datetime, timedelta, date
import time
from cryptocmd import CmcScraper

import traceback

class StockService(object):
	id = "Stock"
	name = "💎 Stocks 💎"
	welcome = "Welcome to Stocks 💎 Service \nWe get you stock information. Send us a stock to get info."
	help = "send a message to get it back"
	imageurl = "https://i.pinimg.com/564x/0e/98/e6/0e98e6518fa8b33dada3ed4104d04da3.jpg"
	shortDescription = "Stock Stock Stock"
	share = None

	examples = {"AAPL":{"text":"","thumbnail":None}, "TSLA":{"text":"","thumbnail":None},"TSLA":{"btc":"","thumbnail":None}}

	def __init__(self,db, api):
		StockService.share = self

		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Stock",StockService.share)
		self.db = db
		self.api = api
		if "upcoming" not in self.db:
			self.db["upcoming"] = []
		if "users" not in self.db:
			self.db["users"] = {}

	def go(self):
		while(True):
			if "upcoming" not in self.db:
				self.db["upcoming"] = []
			if "users" not in self.db:
				self.db["users"] = {}

			while len(self.db["upcoming"]) > 0:
				item = self.db["upcoming"].pop(0)
				origin, content = item
				self.api.send(origin, content, thumnail = "test")
				# self.api.backup(self.db)

			time.sleep(1)

	def process(self, info):
		origin, user, content = None, None, None
		if "origin" in info:
			origin = info["origin"]
		if "user" in info:
			user = info["user"]
		if "content" in info:
			content = info["content"]

		if "users" not in self.db:
			self.db["users"] = {}

		self.api.send(origin, "Fetching Stock for: *"+content+"*")
		# content = "AAPL"

		today = date.today()
		yesterday = datetime.now() - timedelta(1)
		scraper = CmcScraper(content, yesterday.strftime("%d-%m-%Y"),today.strftime("%d-%m-%Y"))
		# scraper = CmcScraper("btc", "28-1-2021","29-1-2021")
		# headers, data = scraper.get_data()
		# scraper.get_data("json")[1:-1]
		# self.api.send(origin, "Could not fetch info for: "+content)
		t = None
		try:
			t = yf.Ticker(content).info
		except :
			return self.api.send(origin, "Could not fetch info for: "+content)

		res = {"dayHigh":"","dayLow":"", "open":"", "regularMarketPrice":"","volume":"","averageVolume10days":""}
		if t is not None and content.lower() not in ["eth"]:
			name = t["longName"]
			for k in res:
				res[k] = t[k]
			res["price"] = res.pop("regularMarketPrice")
			sendBack = str(res).replace("{","").replace("}","").replace(", ","\n").replace("'","")
			logoURL = t["logo_url"]
			sendBack+="\n"+logoURL
			print (sendBack)

			self.api.send(origin, "*"+name+"*\n"+sendBack,thumnail = {"imageurl":logoURL,"title":name+" Stock","desc":"Get More Stock Info","link":logoURL})

		else:
			data = None
			try:
				try:
					headers, data = scraper.get_data()
				except:
					headers, data = scraper.get_data()
			except:
				traceback.print_exc()

			if data is not None:
				res = {}
				ch = 0
				for h in headers:
					res[h] = data[-1][ch]
					ch+=1
				name = content.upper()
				res.pop("Date")
				sendBack = str(res).replace("{","").replace("}","").replace(", ","\n").replace("'","")
				# self.api.send(origin, "*"+name+"*\n"+sendBack,thumnail = {"imageurl":logoURL,"title":name+" Crypto","desc":"Get More Stock Info","link":logoURL})
				return self.api.send(origin, "*"+name+"*\n"+sendBack,thumnail = None)
			else:
				self.api.send(origin, "Could not fetch info for: "+content)

		#
		#
		# sendBack = content
		#
		# withLink = True
		# if withLink:
		# 	answer = ":answerid:555"
		# 	myLink = self.api.genLink(origin, answer)
		# 	sendBack += "\n\n"+answer+":\n"+myLink
		#
		# self.db["upcoming"].append([origin, sendBack])


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
			self.db["users"][origin] = origin
			self.backup()
