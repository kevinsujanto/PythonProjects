from win32com.client import Dispatch

file = raw_input('Path: ')
alphabets = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
numbers = ['0','1','2','3','4','5','6','7','8','9']
for alpha1 in alphabet:
	for alpha2 in alphabets:
		for alpha3 in alphabets:
			for alpha4 in alphabets:
				password = alpha1 + alpha2 + alpha3 + alpha4
                                print("Testing Password: " + password)
				instance = Dispatch('Excel.Application')
				try:
				    	instance.Workbooks.Open(file, False, True, None, password)
			    		print("Password Cracked: " + password)
	    				break
	    			except:
                                        pass

