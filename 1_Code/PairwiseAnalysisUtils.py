import hashlib
import json
import os
import sys

# Analsyis Class
class PairwiseAnalysis:

	# Data
	app1 = None
	app2 = None

	# Extracted Features
	featuresApp1 = None
	featuresApp2 = None

	# Results
	results = None

	# Similarity Scores
	scores = None

	# Init
	def __init__(self, app1, app2):
		self.app1 			= app1
		self.app2 			= app2
		self.featuresApp1 	= {}
		self.featuresApp2 	= {}
		self.results 		= {}
		self.scores  		= {}

	######################################################

	# Setup the analysis
	def runAnalysisSetup(self, silentMode=True):
		# Silent Mode ON
		if silentMode:
			originalStdout = sys.stdout
			sys.stdout = open(os.devnull, 'w')
		
		try:
			print("~~~" * 25)
			print("--- ⚡ [START] Analyis Setup")
			print("--- 📦 pkgName App1 : {}".format(self.app1.pkgName))
			print("--- 🔑 SHA256  App1 : {}".format(self.app1.sha256))
			print("--- 📦 pkgName App2 : {}".format(self.app2.pkgName))
			print("--- 🔑 SHA256  App2 : {}".format(self.app2.sha256))

			# Check if APKs are already downloaded
			self.app1.downloadAPK()
			self.app2.downloadAPK()

			# Check if features file exists, otherwise extract
			app1FeaturesFile = os.path.join(self.app1.apkPath.replace("{}.apk".format(self.app1.sha256), ""), "{}_features.json".format(self.app1.sha256))
			app2FeaturesFile = os.path.join(self.app2.apkPath.replace("{}.apk".format(self.app2.sha256), ""), "{}_features.json".format(self.app2.sha256))
			print("\n--- 📂 Checking if features JSON files are present...")

			# App1
			print("\n--- 📂 Checking App1")
			if not os.path.exists(app1FeaturesFile):
				print("--- ❌ [MISS] Features file for App1 not found --> Extracting...")
				self.app1DecompiledPath 				= self.app1.decompileWithApkTool()
				self.app1_A, self.app1_D, self.app1_X 	= self.app1.analyseWithAndroguard()
			else:
				print("--- ✅ [HIT] Features for App1 loaded successfully.")
				self.app1.decompiledPath = self.app1.apkPath[:-4]
			
			# App2
			print("\n--- 📂 Checking App2")
			if not os.path.exists(app2FeaturesFile):
				print("--- ❌ [MISS] Features file for App2 not found --> Extracting...")
				self.app2DecompiledPath 				= self.app2.decompileWithApkTool()
				self.app2_A, self.app2_D, self.app2_X 	= self.app2.analyseWithAndroguard()
			else:
				print("--- ✅ [HIT] Features for App2 loaded successfully.")
				self.app2.decompiledPath = self.app2.apkPath[:-4]
		
			print("\n\n--- ⚡ [END] Analysis Setup")
			print("~~~" * 25)

		# Silent Mode OFF
		finally:
			if silentMode:
				sys.stdout.close()
				sys.stdout = originalStdout

	# Run the extraction of features
	def runExtraction(self, silentMode=True):
		# Silent mode ON
		if silentMode:
			originalStdout = sys.stdout
			sys.stdout = open(os.devnull, 'w')

		try:
			print("~~~" * 25)
			print("--- ⚡ [START] Extracting Features")

			# Check if features file exists, otherwise extract
			app1FeaturesFile = os.path.join(self.app1.apkPath.replace("{}.apk".format(self.app1.sha256), ""), "{}_features.json".format(self.app1.sha256))
			app2FeaturesFile = os.path.join(self.app2.apkPath.replace("{}.apk".format(self.app2.sha256), ""), "{}_features.json".format(self.app2.sha256))
			print("\n--- 📂 Checking if features JSON files are present...")

			print("\n--- 📂 Checking App1")
			if os.path.exists(app1FeaturesFile):
				# Success
				with open(app1FeaturesFile, 'r') as f:
					self.featuresApp1 = json.load(f)
				print("--- ✅ [HIT]  Features for App1 loaded successfully.")
			else:
				# Not Success
				print("--- ❌ [MISS] Features file for App1 not found --> Extracting...")

				# Extract features
				self.featuresApp1 = self.app1.extractAllFeatures()

				# Save features to JSON file
				with open(app1FeaturesFile, 'w') as f:
					json.dump(convertSets(self.featuresApp1), f, indent=4)
				print("--- 💾 Features of App1 saved to: {}".format(app1FeaturesFile))

			# Check and load features for App2
			print("\n--- 📂 Checking App2")
			if os.path.exists(app2FeaturesFile):
				# Success
				with open(app2FeaturesFile, 'r') as f:
					self.featuresApp2 = json.load(f)
				print("--- ✅ [HIT]  Features for App2 loaded successfully.")
			else:
				# Not Success
				print("--- ❌ [MISS] Features file for App2 not found --> Extracting...")

				# Extract features
				self.featuresApp2 = self.app2.extractAllFeatures()

				# Save features to JSON file
				with open(app2FeaturesFile, 'w') as f:
					json.dump(convertSets(self.featuresApp2), f, indent=4)
				print("--- 💾 Features of App2 saved to: {}".format(app2FeaturesFile))

			print("\n\n--- ⚡ [END] Extracting Features")
			print("~~~" * 25)

		# Silent Mode OFF
		finally:
			if silentMode:
				sys.stdout.close()
				sys.stdout = originalStdout

	# Run all the phases of the analysis
	def runComparison(self, silentMode=True):
		# Silent Mode ON
		if silentMode:
			originalStdout = sys.stdout
			sys.stdout = open(os.devnull, 'w')

		try:
			print("~~~" * 25)
			print("--- ⚡ [START] Comparing Features\n")

			print("--- ⚖️ Comparing --> APK Certificates")
			self.results['certificates'] = self.compareApkCertificates()
			print("\n" + "---" * 20)

			print("--- ⚖️ Comparing --> Permissions")
			self.results['permissions'] = self.comparePermissions()
			print("\n" + "---" * 20)

			print("--- ⚖️ Comparing --> Components")
			self.results['components'] = self.compareComponents()
			print("\n" + "---" * 20)

			print("--- ⚖️ Comparing --> Files")
			self.results['files'] = self.compareFiles()
			print("\n" + "---" * 20)

			print("--- ⚖️ Comparing --> Smali Files")
			self.results['smaliFiles'] = self.compareSmaliFiles()
			print("\n" + "---" * 20)

			print("--- ⚖️ Comparing --> Native Libs")
			self.results['nativeLibs'] = self.compareNativeLibraries()
			print("\n" + "---" * 20)

			print("--- ⚖️ Comparing --> 3rd-party Libs")
			self.results['thirdPartyLibs'] = self.compareThirdPartyLibraries()
			print("\n" + "---" * 20)

			print("--- ⚖️ Comparing --> URLs")
			self.results['URLs'] = self.compareURLs()
			print("\n" + "---" * 20)

			print("\n\n--- ⚡ [END] Comparing Features")
			print("~~~" * 25)
		
		# Silent Mode OFF
		finally:
			if silentMode:
				sys.stdout.close()
				sys.stdout = originalStdout

	# Run the Computation of scores
	def runScoresComputation(self, silentMode=True):
		# Silent Mode ON
		if silentMode:
			originalStdout = sys.stdout
			sys.stdout = open(os.devnull, 'w')

		try:
			print("~~~" * 25)
			print("--- ⚡ [START] Computing Scores\n")

			print("--- 📐 Computing Score --> APK Certificates")
			self.scores['certificates'] = self.computeScoreApkCertificates()
			print("\n" + "---" * 20)

			print("--- 📐 Computing Score --> Permissions")
			self.scores['permissions'] = self.computeScorePermissions()
			print("\n" + "---" * 20)

			print("--- 📐 Computing Score --> Components")
			self.scores['components'] = self.computeScoreComponents()
			print("\n" + "---" * 20)

			print("--- 📐 Computing Score --> Files")
			self.scores['files'] = self.computeScoreFiles()
			print("\n" + "---" * 20)

			print("--- 📐 Computing Score --> Smali Files")
			self.scores['smaliFiles'] = self.computeScoreSmaliFiles()
			print("\n" + "---" * 20)

			print("--- 📐 Computing Score --> Native Libraries")
			self.scores['nativeLibs'] = self.computeScoreNativeLibraries()
			print("\n" + "---" * 20)

			print("--- 📐 Computing Score --> Third-Party Libraries")
			self.scores['thirdPartyLibs'] = self.computeScoreThirdPartyLibraries()
			print("\n" + "---" * 20)

			print("--- 📐 Computing Score --> URLs")
			self.scores['URLs'] = self.computeScoreURLs()
			print("\n" + "---" * 20)
				
			# OVERALL SCORE
			print("--- 📐 Computing --> OVERALL SCORE")
			overallScore = self.computeoverallScore()
			self.scores['overallScore'] = overallScore

			print("\n\n--- ⚡ [END] Computing Scores")
			print("~~~" * 25)

		# Silent Mode OFF
		finally:
			if silentMode:
				sys.stdout.close()
				sys.stdout = originalStdout

	# Clean up the analysis
	def runCleaning(self, silentMode=True):
		# Silent Mode ON
		if silentMode:
			originalStdout = sys.stdout
			sys.stdout = open(os.devnull, 'w')
			
		try:
			# Clean up the analysis
			print("\n--- 🗑️ [CLEANING]")
			self.app1.deleteAll()
			self.app1.deleteAPK()
			self.app2.deleteAll()
			self.app2.deleteAPK()

		# Silent Mode OFF
		finally:
			if silentMode:
				sys.stdout.close()
				sys.stdout = originalStdout

	######################################################

	### COMPARISON FUNCTIONS ###
	# Function to compare certificates
	def compareApkCertificates(self):
		parsedCerts1 = self.featuresApp1['certificates']
		parsedCerts2 = self.featuresApp2['certificates']

		sameSerialNumbers 	= all(cert1['serialNumber'] == cert2['serialNumber'] for cert1, cert2 in zip(parsedCerts1, parsedCerts2))
		sameIssuers 		= all(cert1['issuer'] 		== cert2['issuer'] 		 for cert1, cert2 in zip(parsedCerts1, parsedCerts2))
		samePublicKeys 		= all(cert1['publicKey'] 	== cert2['publicKey'] 	 for cert1, cert2 in zip(parsedCerts1, parsedCerts2))
		
		print("------ 📌 Same Serial Numbers : {}".format(sameSerialNumbers))
		print("------ 📌 Same Issuers        : {}".format(sameIssuers))
		print("------ 📌 Same Public Keys    : {}".format(samePublicKeys))
			
		print("------ 📌 Certificates Issuers in APK 1 [{}]:".format(len(parsedCerts1)))
		for cert in parsedCerts1:
			print(json.dumps(cert['issuer'], indent=4))
		print("------ 📌 Certificates Issuers in APK 2 [{}]:".format(len(parsedCerts2)))
		for cert in parsedCerts2:
			print(json.dumps(cert['issuer'], indent=4))

		result = {
			'certsInApp1'		: parsedCerts1,
			'certsInApp2'		: parsedCerts2,
			'sameSerialNumbers'	: sameSerialNumbers,
			'sameIssuers'		: sameIssuers,
			'samePublicKeys': samePublicKeys,
		}

		return result

	# Function to compare permissions between two Android packages
	def comparePermissions(self):
		# Get Permissions from Androguard
		permissionsApp1 = set(self.featuresApp1['permissions'])
		permissionsApp2 = set(self.featuresApp2['permissions'])

		# Compare Permissions
		onlyInApp1 	= permissionsApp1 - permissionsApp2
		onlyInApp2 	= permissionsApp2 - permissionsApp1
		inCommon 	= permissionsApp1 & permissionsApp2

		# Check if only difference is package name
		onlyInApp1, onlyInApp2, inCommon = self.checkForPkgNameInSets(onlyInApp1, onlyInApp2, inCommon)
		
		print("------ 📌 Permissions only in {} [{}]:".format(self.app1.pkgName, len(onlyInApp1)))
		print(list(onlyInApp1))
		print("\n------ 📌 Permissions only in {} [{}]:".format(self.app2.pkgName, len(onlyInApp2)))
		print(list(onlyInApp2))
		print("\n------ 📌 Common Permissions [{}]:".format(len(inCommon)))
		print(list(inCommon))

		# Create Results Dictionary
		result = {
			'onlyInApp1': onlyInApp1,
			'onlyInApp2': onlyInApp2,
			'inCommon'  : inCommon
		}

		# Return Results
		return result
	
	# Function to compare component names between two Android packages using Androguard
	def compareComponents(self):
		components1 = self.featuresApp1['components']
		components2 = self.featuresApp2['components']
		results    = {}

		# Transform components into sets
		for componentType in components1.keys():
			components1[componentType] = set(components1[componentType])
			components2[componentType] = set(components2[componentType])

		for componentType in components1.keys():
			onlyInFirst  = components1[componentType] - components2[componentType]
			onlyInSecond = components2[componentType] - components1[componentType]
			inCommon     = components1[componentType] & components2[componentType]

			# Check if only difference is package name
			onlyInFirst, onlyInSecond, inCommon = self.checkForPkgNameInSets(onlyInFirst, onlyInSecond, inCommon)

			print("\n--- 🔍 {} Comparison:".format(componentType.capitalize()))
			print("------ 📌 {} only in {} [{}]:".format(componentType.capitalize(), self.app1.pkgName, len(onlyInFirst)))
			print(list(onlyInFirst))
			print("\n------ 📌 {} only in {} [{}]:".format(componentType.capitalize(), self.app2.pkgName, len(onlyInSecond)))
			print(list(onlyInSecond))
			print("\n------ 📌 Common {} [{}]:".format(componentType.capitalize(), len(inCommon)))
			print(list(inCommon))

			results[componentType] = {
				'onlyInFirst': onlyInFirst,
				'onlyInSecond': onlyInSecond,
				'inCommon': inCommon
			}

		return results

	# Function to compare files between two Android packages using Androguard
	def compareFiles(self):
		filesApp1 = set(self.featuresApp1['files'])
		filesApp2 = set(self.featuresApp2['files'])

		# Compare Files
		onlyInApp1 = filesApp1 - filesApp2
		onlyInApp2 = filesApp2 - filesApp1
		inCommon   = filesApp1 & filesApp2

		print(f"Files found only in {self.app1.pkgName}: {onlyInApp1}")
		print(f"Files found only in {self.app2.pkgName}: {onlyInApp2}")

		# Check if only difference is package name
		onlyInApp1, onlyInApp2, inCommon = self.checkForPkgNameInSets(onlyInApp1, onlyInApp2, inCommon)

		print(f"Files found only in {self.app1.pkgName} w/out package name: {onlyInApp1}")
		print(f"Files found only in {self.app2.pkgName} w/out package name: {onlyInApp2}")
		
		print("------ 📌 Files only in {} [{}]".format(self.app1.pkgName, len(onlyInApp1)))
		print("------ 📌 Files only in {} [{}]".format(self.app2.pkgName, len(onlyInApp2)))
		print("------ 📌 Common Files [{}]".format(len(inCommon)))

		# Check if files are actually the same
		sameFiles = set()
		for file in inCommon:
			filePath1 = os.path.join(self.app1.decompiledPath, file)
			filePath2 = os.path.join(self.app2.decompiledPath, file)
			if compareFilesByHash(filePath1, filePath2):
				sameFiles.add(file)
		
		# Calculate non-identical common files
		nonIdenticalFiles = inCommon - sameFiles

		print(f"------ 📌 Non-Identical Common Files: {nonIdenticalFiles}")

		print("------ 📌 Identical Common Files     [{:<6}]/[{:<6}] --> ({:.2f}%)".format(len(sameFiles), len(inCommon), (len(sameFiles) / len(inCommon) * 100) if len(inCommon) > 0 else 0))
		print("------ 📌 Non-Identical Common Files [{:<6}]/[{:<6}] --> ({:.2f}%)".format(len(nonIdenticalFiles), len(inCommon), (len(nonIdenticalFiles) / len(inCommon) * 100) if len(inCommon) > 0 else 0))
		
		result = {
			'onlyInFirst'				: onlyInApp1,
			'onlyInSecond'				: onlyInApp2,
			'inCommon'  				: inCommon,
			'identicalCommonFiles'		: sameFiles,
			'nonIdenticalCommonFiles'	: nonIdenticalFiles
		}

		return result
		
	# Function to compare .smali files between two Android packages
	def compareSmaliFiles(self):
		smaliFiles1 = set(self.featuresApp1['smaliFiles'])
		smaliFiles2 = set(self.featuresApp2['smaliFiles'])
		
		onlyInFirst  = smaliFiles1 - smaliFiles2
		onlyInSecond = smaliFiles2 - smaliFiles1
		inCommon     = smaliFiles1 & smaliFiles2

		print(f"Files found only in {self.app1.pkgName}: {onlyInFirst}")
		print(f"Files found only in {self.app2.pkgName}: {onlyInSecond}")
		
		print("------ 📌 Smali Files only in {} [{}]:".format(self.app1.pkgName, len(onlyInFirst)))
		print("------ 📌 Smali Files only in {} [{}]:".format(self.app2.pkgName, len(onlyInSecond)))
		print("------ 📌 Common Smali Files [{}]:".format(len(inCommon)))
		
		# Check if common smali files are actually the same
		sameFiles = set()
		for file in inCommon:
			filePath1 = os.path.join(self.app1.decompiledPath, file)
			filePath2 = os.path.join(self.app2.decompiledPath, file)
			if compareFilesByHash(filePath1, filePath2):
				sameFiles.add(file)
		
		# Calculate non-identical common smali files
		nonIdenticalFiles = inCommon - sameFiles

		print(f"------ 📌 Non-Identical Common Files: {nonIdenticalFiles}")

		print("------ 📌 Identical Common Files     [{:<6}]/[{:<6}] --> ({:.2f}%)".format(len(sameFiles), len(inCommon), (len(sameFiles) / len(inCommon) * 100) if len(inCommon) > 0 else 0))
		print("------ 📌 Non-Identical Common Files [{:<6}]/[{:<6}] --> ({:.2f}%)".format(len(nonIdenticalFiles), len(inCommon), (len(nonIdenticalFiles) / len(inCommon) * 100) if len(inCommon) > 0 else 0))
		
		result = {
			'onlyInFirst'        		: onlyInFirst,
			'onlyInSecond'       		: onlyInSecond,
			'inCommon'           		: inCommon,
			'identicalCommonFiles'		: sameFiles,
			'nonIdenticalCommonFiles' 	: nonIdenticalFiles
		}
		
		return result

	# Function to compare native libraries between two Android packages
	def compareNativeLibraries(self):
		soFiles1 = set(self.featuresApp1['nativeLibs'])
		soFiles2 = set(self.featuresApp2['nativeLibs'])

		onlyInFirst 	= soFiles1 - soFiles2
		onlyInSecond 	= soFiles2 - soFiles1
		inCommon 	    = soFiles1 & soFiles2

		print("------ 📌 Native Libraries only in {} [{}]:".format(self.app1.pkgName, len(onlyInFirst)))
		print(list(onlyInFirst))
		print("\n------ 📌 Native Libraries only in {} [{}]:".format(self.app2.pkgName, len(onlyInSecond)))
		print(list(onlyInSecond))
		print("\n------ 📌 Common Native Libraries [{}]:".format(len(inCommon)))
		print(list(inCommon))

		result = {
			'onlyInFirst': onlyInFirst,
			'onlyInSecond': onlyInSecond,
			'inCommon': inCommon
		}
		
		return result

	# Fucntion to compare third party libraries using AndroLibZoo
	def compareThirdPartyLibraries(self):
		thirdParty1 = set(self.featuresApp1['thirdPartyLibs'])
		thirdParty2 = set(self.featuresApp2['thirdPartyLibs'])

		onlyInApp1 	= thirdParty1 - thirdParty2
		onlyInApp2 	= thirdParty2 - thirdParty1
		inCommon	= thirdParty1 & thirdParty2

		print("------ 📌 Third-Party Libraries only in {} [{}]:".format(self.app1.pkgName, len(onlyInApp1)))
		print(list(onlyInApp1))
		print("\n------ 📌 Third-Party Libraries only in {} [{}]:".format(self.app2.pkgName, len(onlyInApp2)))
		print(list(onlyInApp2))
		print("\n------ 📌 Common Third-Party Libraries [{}]:".format(len(inCommon)))
		print(list(inCommon))
		result = {
				'onlyInApp1': onlyInApp1, 
				'onlyInApp2': onlyInApp2, 
				'inCommon': inCommon
		}
		return result

	# Function to compare URLs between two Android packages
	def compareURLs(self):
		urls1 = set(self.featuresApp1['URLs'])
		urls2 = set(self.featuresApp2['URLs'])

		onlyInApp1 = urls1 - urls2
		onlyInApp2 = urls2 - urls1
		inCommon   = urls1 & urls2

		print("------ 📌 URLs only in {} [{}]:".format(self.app1.pkgName, len(onlyInApp1)))
		print(list(onlyInApp1))
		print("\n------ 📌 URLs only in {} [{}]:".format(self.app2.pkgName, len(onlyInApp2)))
		print(list(onlyInApp2))
		print("\n------ 📌 Common URLs [{}]:".format(len(inCommon)))
		print(list(inCommon))

		result = {
			'onlyInApp1': onlyInApp1,
			'onlyInApp2': onlyInApp2,
			'inCommon': inCommon
		}

		return result

	# Function to check if the only difference between two sets is the package name
	def checkForPkgNameInSets(self, set1, set2, commonSet):
		list1 = list(set1)
		list2 = list(set2)
		commonList = list(commonSet)

		for string1 in list1[:]:
			for string2 in list2[:]:
				remainingString1 = string1.replace(self.app1.pkgName, '')
				remainingString2 = string2.replace(self.app2.pkgName, '')
				if remainingString1 == remainingString2:
					list1.remove(string1)
					list2.remove(string2)
					commonString = "[PKG_NAME]{}".format(remainingString1)

					# print("---FOUND!")
					# print(string1, string2)
					# print(remainingString1, remainingString2)
					# print(commonString)

					# Add the common string to the common list
					commonList.append(commonString)

		return set(list1), set(list2), set(commonList)

	########################################################

	### SCORING FUNCTIONS ###
	# Compute Overall Score
	def computeoverallScore(self):
		# TODO: add weight
		
		# Calculate final score
		totalScore = 0
		for key, score in self.scores.items():
			print("--- 🎯 Score - {:20} : {:.2f}".format(key.capitalize(), score))
			totalScore += score
		overallScore = totalScore / len(self.scores)
		
		print("\n--- 🎯 OVERALL SCORE: {:.2f}".format(overallScore))
		return overallScore

		# Get score for native libraries using Jaccard index
	
	# Get score for APK certificates using Jaccard index
	def computeScoreApkCertificates(self):
		# Get Results
		result = self.results['certificates']
		certsInApp1 = result['certsInApp1']
		certsInApp2 = result['certsInApp2']

		# Compare certificates using compareJsonObjects
		similarityScores = []
		for cert1, cert2 in zip(certsInApp1, certsInApp2):
			#Test purposes
			# print("------ 📌 Certificate 1:")
			# print(json.dumps(cert1, indent=4))
			# print("------ 📌 Certificate 2:")
			# print(json.dumps(cert2, indent=4))

			# Compare issuer
			similarityScores.append(compareJsonObjects({'issuer': cert1['issuer']}, {'issuer': cert2['issuer']}))
		
		# Calculate average similarity score
		score = sum(similarityScores) / len(similarityScores) if similarityScores else 0

		print("------ 🎯 APK Certificates Score: {:.2f}".format(score))
	
		return score
	
	# Get score for Permissions using Jaccard Index
	def computeScorePermissions(self):
		# Get Results
		result 		= self.results['permissions']
		onlyInApp1 	= result['onlyInApp1']
		onlyInApp2 	= result['onlyInApp2']
		inCommon 	= result['inCommon']

		# Check if none of the apps are using Permissions
		if len(onlyInApp1) == 0 and len(onlyInApp2) == 0 and len(inCommon) == 0:
			return 1.0

		# Calculate Jaccard similarity score
		union = len(onlyInApp1) + len(onlyInApp2) + len(inCommon)
		intersection = len(inCommon)
		score = intersection / union if union > 0 else 0

		print("------ 🎯 Permissions Score: {:.2f}".format(score))
		return score
	
	# Get score for components using Jaccard index
	def computeScoreComponents(self):
		# Initialize variables
		totalWeightedScore = 0
		totalComponents    = 0

		# Iterate through each component type
		for componentType, result in self.results['components'].items():
			onlyInApp1 	= result['onlyInFirst']
			onlyInApp2 	= result['onlyInSecond']
			inCommon 	= result['inCommon']
			
			# Check if none of the apps are using this component type
			if len(onlyInApp1) == 0 and len(onlyInApp2) == 0 and len(inCommon) == 0:
				print("------ 🎯 {:<10} Score: {:.2f} (Weight: 0)".format(componentType.capitalize(), 1.0))
				continue
			
			# Calculate Jaccard similarity score for the current component type
			union = len(onlyInApp1) + len(onlyInApp2) + len(inCommon)
			intersection = len(inCommon)
			score = intersection / union if union > 0 else 0

			# Calculate the weight based on the total number of components of this type
			componentCount = len(onlyInApp1) + len(onlyInApp2) + len(inCommon)
			totalWeightedScore += score * componentCount
			totalComponents += componentCount

			# Print the score for the current component type
			print("------ 🎯 {:<10} Score: {:.2f} (Weight: {})".format(componentType.capitalize(), score, componentCount))

		# Check if all scores are 1
		if all(score == 1.0 for score in self.scores.values()):
			#print("------ 🎯 All Scores are 1. Returning 1.0 as the overall score.")
			return 1.0

		# Calculate and return the weighted average score
		averageScore = totalWeightedScore / totalComponents

		print("------ 🎯 Overall Components Score: {:.2f}".format(averageScore))

		return averageScore
	
	# Get score for files using Jaccard index (weighted)
	def computeScoreFiles(self):
		# Get Results
		result 				= self.results['files']
		onlyInApp1 			= result['onlyInFirst']
		onlyInApp2 			= result['onlyInSecond']
		inCommon 			= result['inCommon']
		identicalFiles 		= result['identicalCommonFiles']
		nonIdenticalFiles 	= result['nonIdenticalCommonFiles']

		# Check if none of the apps have smali files
		if len(onlyInApp1) == 0 and len(onlyInApp2) == 0 and len(inCommon) == 0:
			return 1.0
	
		# Calculate the smali score based on the given formula
		totalFiles = len(onlyInApp1) + len(onlyInApp2) + len(inCommon)
		score = (
			(1.0 * len(identicalFiles)) +
			(0.5 * len(nonIdenticalFiles)) +
			(0.0 * (len(onlyInApp1) + len(onlyInApp2)))
		) / totalFiles if totalFiles > 0 else 0

		print("------ 🎯 Files Score: {:.2f}".format(score))
	
		return score
	
	# Get score for smali files using Jaccard index (weighted)
	def computeScoreSmaliFiles(self):
		# Get Results
		result 				= self.results['smaliFiles']
		onlyInApp1 			= result['onlyInFirst']
		onlyInApp2 			= result['onlyInSecond']
		inCommon 			= result['inCommon']
		identicalFiles 		= result['identicalCommonFiles']
		nonIdenticalFiles 	= result['nonIdenticalCommonFiles']


		# Check if none of the apps have smali files
		if len(onlyInApp1) == 0 and len(onlyInApp2) == 0 and len(inCommon) == 0:
			return 1.0
	
		# Calculate the smali score based on the given formula
		totalFiles = len(onlyInApp1) + len(onlyInApp2) + len(inCommon)
		score = (
			(1.0 * len(identicalFiles)) +
			(0.5 * len(nonIdenticalFiles)) +
			(0.0 * (len(onlyInApp1) + len(onlyInApp2)))
		) / totalFiles if totalFiles > 0 else 0

		print("------ 🎯 Smali Files Score: {:.2f}".format(score))
	
		return score
	
	# Get score for native libraries using Jaccard index
	def computeScoreNativeLibraries(self):
		# Get Results
		result 	   	= self.results['nativeLibs']
		onlyInApp1 	= result['onlyInFirst']
		onlyInApp2 	= result['onlyInSecond']
		inCommon   	= result['inCommon']

		# Check if none of the apps are using native libraries
		if len(onlyInApp1) == 0 and len(onlyInApp2) == 0 and len(inCommon) == 0:
			return 1.0

		# Calculate Jaccard similarity score
		union 			= len(onlyInApp1) + len(onlyInApp2) + len(inCommon)
		intersection 	= len(inCommon)
		score 			= intersection / union if union > 0 else 0

		print("------ 🎯 Native Libraries Score: {:.2f}".format(score))
	
		return score
	
	# Get score for third-party libraries using Jaccard index
	def computeScoreThirdPartyLibraries(self):
		# Get Results
		result 		= self.results['thirdPartyLibs']
		onlyInApp1 	= result['onlyInApp1']
		onlyInApp2 	= result['onlyInApp2']
		inCommon 	= result['inCommon']

		# Check if none of the apps are using libraries
		if len(onlyInApp1) == 0 and len(onlyInApp2) == 0 and len(inCommon) == 0:
			return 1.0

		# Calculate Jaccard similarity score
		union = len(onlyInApp1) + len(onlyInApp2) + len(inCommon)
		intersection = len(inCommon)
		score = intersection / union if union > 0 else 0

		print("------ 🎯 Third-Party Libraries Score: {:.2f}".format(score))
	
		return score
	
	# Get score for URLs using Jaccard index
	def computeScoreURLs(self):
		# Get Results
		result 		= self.results['URLs']
		onlyInApp1 	= result['onlyInApp1']
		onlyInApp2 	= result['onlyInApp2']
		inCommon 	= result['inCommon']

		# Check if none of the apps are using URLs
		if len(onlyInApp1) == 0 and len(onlyInApp2) == 0 and len(inCommon) == 0:
			return 1.0

		# Calculate Jaccard similarity score
		union = len(onlyInApp1) + len(onlyInApp2) + len(inCommon)
		intersection = len(inCommon)
		score = intersection / union if union > 0 else 0

		print("------ 🎯 URLs Score: {:.2f}".format(score))
	
		return score

######################################################################

### UTILS ###
# Function to compare two files by their hash
def compareFilesByHash(path1, path2):
	# Compute md5 hash
	def computeFileHash(filePath):
		# Compute abs path
		filePath = os.path.abspath(filePath)
		if not os.path.exists(filePath):
			return None
		with open(filePath, 'rb') as f:
			return hashlib.md5(f.read()).hexdigest()
		
	hash1 = computeFileHash(path1)
	hash2 = computeFileHash(path2)

	if hash1 is None or hash2 is None:
		return False
	
	return hash1 == hash2

# Function to compare two JSON objects and calculate similarity
def compareJsonObjects(json1, json2):

	#Flatten a nested JSON object into a single dictionary.
	def flattenJson(jsonObj, parentKey='', sep='.'):
		items = []
		for k, v in jsonObj.items():
			newKey = "{}{}{}".format(parentKey, sep, k) if parentKey else k
			if isinstance(v, dict):
				items.extend(flattenJson(v, newKey, sep=sep).items())
			else:
				items.append((newKey, v))
		return dict(items)
	
	# Flatten both JSON objects
	flatJson1 = flattenJson(json1)
	flatJson2 = flattenJson(json2)

	# Calculate intersection and union of keys
	keys1 = set(flatJson1.keys())
	keys2 = set(flatJson2.keys())
	commonKeys 	= keys1 & keys2
	allKeys 	= keys1 | keys2

	# Calculate similarity based on common keys and values
	matchingValues = sum(1 for key in commonKeys if flatJson1[key] == flatJson2[key])
	similarityScore = matchingValues / len(allKeys) if allKeys else 0

	return similarityScore

# Function Convert sets to lists in a nested JSON object
def convertSets(obj):
	if isinstance(obj, dict):
		return {k: convertSets(v) for k, v in obj.items()}
	elif isinstance(obj, set):
		return list(obj)
	elif isinstance(obj, list):
		return [convertSets(i) for i in obj]
	else:
		return obj