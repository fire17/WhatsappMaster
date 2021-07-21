#CrystalVisionService.py

import time
import requests
import json
from websocket import create_connection

class CrystalVisionService(object):
	id = "CrystalVision"
	name = "CrystalVision!"
	welcome = "*Welcome to CrystalVision! Service* \n\nשלחו לנו פקודות בכדי לתקשר עם CrystalVision API"
	help = "CrystalVision help message"
	imageurl = "https://colors.crystalvision.co.il/static/crystalvision-logo.webp"
	shortDescription = "CrystalVision Robotic Service"
	share = None

	examples = {"_":{"text":"Hello World","thumbnail":None}}

	def __init__(self,db, api):
		CrystalVisionService.share = self

		self.robots = {"r1":"","r2":"","r3":"","r4":""}
		self.tags = {"Feeder 1":{
		"_AMOUNT_LEFT_TO_FEED_1":"Amount Left To Feed",
		"_DAILY_AMOUNT_1":"Daily amount",
		"_ACCUMULATED_AMOUNT_1":"Accumulated amount",
		"_MEAL_AMOUNT_1":"Meal amount",
		"_LAST_DAY_AMOUNT_1":"Last Day amount",
		},
		"Feeder 2":{
		"_AMOUNT_LEFT_TO_FEED_2":"Amount Left To Feed",
		"_DAILY_AMOUNT_2":"Daily amount",
		"_ACCUMULATED_AMOUNT_2":"Accumulated amount",
		"_MEAL_AMOUNT_2":"Meal amount" ,
		"_LAST_DAY_AMOUNT_2":"Last Day amount",
		},
		"Feeder 3":{
		"_AMOUNT_LEFT_TO_FEED_3":"Amount Left To Feed",
		"_DAILY_AMOUNT_3":"Daily amount",
		"_ACCUMULATED_AMOUNT_3":"Accumulated amount",
		"_MEAL_AMOUNT_3":"Meal amount" ,
		"_LAST_DAY_AMOUNT_3":"Last Day amount"
		}}


		print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! CrystalVision",CrystalVisionService.share)
		self.db = db
		self.api = api
		if "upcoming" not in self.db:
			self.db["upcoming"] = []
		if "users" not in self.db:
			self.db["users"] = {}

	def go(self):
		while(False):
			pass

	def strRange(self, i):
		x = []
		for a in range(i):
			x.append(str(a+1))
		return x

	def translateTag(self, content):
		return content

	def formatMessage(self, data, robot, pool):
		# id =
		done = True
		# data = json.loads(serverData)["Tags"]
		resDict = {}
		sendBack = ""
		if "Tags" in data:
			for d in data["Tags"]:
				print("D:",d)
				if "tagName" in d:
					unit = d["unit"]
					if unit == "" or unit == "0":
						unit = ""
					resDict[d["tagName"]] = d["value"]+unit
					print("t:",d["tagName"],resDict[d["tagName"]])
					print()
			print("resDict",resDict)
			rid = "ROBOT_"+robot+"_ROW"+pool
			for feeder in self.tags:
				sendBack += "*"+feeder+"*:\n"
				for key in self.tags[feeder]:
					print("v:value",key)
					resKey = rid+key
					if resKey in resDict:
						sendBack += self.tags[feeder][key]+": *"+resDict[resKey]+"*\n"
				sendBack += "\n"

		return done, sendBack

	def getCmdForTags(self, tags):
		data = {"command":"getMultipleTagValues","tags":tags,"sender":"web","id":92370}
		# data = {"command":"getTagValue","tagName":code,"sender":"web","id":92370}
		# data = {"command":"getTagValue","tagName":code,"sender":"web","id":92370}
		datax = json.dumps(data).encode('utf-8')
		return datax

	def getDataFromServer(self, code=None, cmd = None):
		if cmd is None:
			data = {"command":"getTagValue","tagName":code,"sender":"web","id":92370}
			datax = json.dumps(data).encode('utf-8')
		else:
			datax = cmd
		CrystalVisionIP = "wss://colors.crystalvision.co.il/ws/crystalweb"
		ws = create_connection(CrystalVisionIP)
		print("Sending data")
		ws.send(datax)
		print("Sent")
		print("Receiving...")
		result =  ws.recv()
		resultDict = json.loads(result)
		print(resultDict)
		return resultDict

	def getRowID(self, code):
		pass

	def AllTagsList(self, robot, row):
		tagList = []
		for feeder in self.tags:
			for key in self.tags[feeder]:
				tagList.append("ROBOT_"+str(robot)+"_ROW"+str(row)+key)
				# tagList.append("ROBOT_"+str(robot)+"_ROW_"+str(row)+"_FISH_CELL_ID")
		return tagList


	def process(self, info):
		origin, user, content = None, None, None
		if "origin" in info:
			origin = info["origin"]
		if "user" in info:
			user = info["user"]
		if "content" in info:
			content = info["content"]

		baseLink = "https://"+self.api.genLink(origin)

		if content.lower().split("/")[0] in self.robots:
			robot = int(content.lower().split("/")[0].replace("r",""))
			if len(content.split("/")) > 1 and content.split("/")[1].replace("pool","") in self.strRange(10):
				pool = int(content.split("/")[1].replace("pool",""))
				rrid = self.getDataFromServer(code = "ROBOT_"+str(robot)+"_ROW_"+str(pool)+"_FISH_CELL_ID")
				print("RRRRRRR",rrid)
				dval = ""
				if "data" in rrid and "value" in rrid["data"]:
					dval = rrid["data"]["value"]
				allTags = self.AllTagsList(robot, pool)
				code = self.getCmdForTags(allTags)
				print("SENDING TO CRYSTAL:",code)
				# self.api.send(origin, "SENDING:\n\n"+str(code))
				# code = self.translateTag(content)
				serverData = self.getDataFromServer(cmd = code)
				done, sendBack = self.formatMessage(serverData, str(robot),str(pool))
				if len(dval) > 3:
					return self.api.send(origin, "*Robot "+str(robot)+" at Pool "+dval[2:4]+"-"+dval[4:]+":*\n\n"+sendBack)
				return self.api.send(origin, "*Robot "+str(robot)+" Pool "+str(pool)+":*\n\n"+sendBack)

			else:
				baseLink+= "r"+str(robot)
				sendBack = "*Robot "+str(robot)+":* \n"
				sendBack += "*Please choose pool:* \n"
				idTags = []
				for i in range(10):
					idTags.append("ROBOT_"+str(robot)+"_ROW_"+str(i+1)+"_FISH_CELL_ID")

				code = self.getCmdForTags(idTags)
				serverData = self.getDataFromServer(cmd = code)
				print("!!!!!\n"+str(serverData))
				if "Tags" in serverData:
					for d in serverData["Tags"]:
						if "tagName" in d:
							dval = d["value"]
							print("dval",dval)
							if len(dval) > 3:
								sendBack += "\nPool "+dval[2:4]+"-"+dval[4:]+" "+baseLink+"/pool"+d["tagName"].split("ROW_")[1].split("_FISH")[0]
				return self.api.send(origin, sendBack)
		else:
			sendBack = "*Please choose Robot:* \n"
			for i in range(4):
				sendBack += "\nRobot "+str(i+1)+" "+baseLink+"r"+str(i+1)
			return self.api.send(origin, sendBack)






		# try:


		# except:


		sendBack = ""
		print("Received \n", result)

		try:
			sendBack += "*"+resultDict["data"]["tagName"] +"* : "+resultDict["data"]["value"]+"\n\n"
		except:
			sendBack = str(resultDict)

		ws.close()
		self.api.send(origin, "GOT BACK:\n\n"+sendBack)


		self.api.genLink(origin)


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
