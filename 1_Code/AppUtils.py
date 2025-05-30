from 	androguard.misc import AnalyzeAPK
from 	asn1crypto.x509 import Certificate
from   	dotenv        	import load_dotenv
import 	subprocess
import 	requests
import 	shutil
import 	urllib
import 	time
import 	os
import 	re

# App Class
class App:

	# Fields
	sha256            = None
	pkgName           = None
	apkPath           = None
	alreadyDownloaded = False
	decompiledPath	  = None

	# Androguard Analysis
	app_A = None
	app_D = None
	app_X = None

	# Initialize the App object.
	def __init__(self, sha256, pkgName, tmpPath, downloadedApkPath = None):
		self.sha256  = sha256
		self.pkgName = pkgName
		self.apkPath = tmpPath + sha256 + ".apk"

		# If the app is already Downloaded somewhere:
		if downloadedApkPath is not None:
			#print("--- 📤 APK file already downloaded.")
			shutil.copy(downloadedApkPath, self.apkPath)
			self.alreadyDownloaded = True

	##################################

	# Download APK File from AndroZoo.
	def downloadAPK(self):
		print("\n--- ⭕ [Running] Download from AZ.")

		MAX_RETRIES = 10
		RETRY_DELAY = 30  # Seconds
		
		# Load AndroZoo API KEY
		load_dotenv()
		apiKey = os.getenv("ANDROZOO_API_KEY")
		sha256 = self.sha256
		
		# Check if the file already exists
		if os.path.exists(self.apkPath):
			print("--- 📤 APK file with SHA256 already exists.")
			return

		# Define request parameters and headers
		params  = {"apikey": apiKey, "sha256": sha256}
		headers = {"User-Agent": "Wget/1.21.1 (linux-gnu)"}
		
		retries = 0
		while retries < MAX_RETRIES:
			print("--- 🔄 Attempt N: {}".format(retries + 1))
			
			try:
				# Attempt to download from the first URL
				response = requests.get("http://serval10.uni.lu/api/download", params=params, headers=headers, timeout=1)
			except requests.RequestException:
				# Fall back to the second URL if the first one fails
				response = requests.get("http://androzoo.uni.lu/api/download", params=params, headers=headers, timeout=10)

			# Check for HTTP errors
			if response.status_code in [502, 503]:
				print("--- ⚠️ [Error] Androzoo: Received status code {}. Retrying in {} seconds...".format(response.status_code, RETRY_DELAY))
				retries += 1
				time.sleep(RETRY_DELAY)
			elif response.status_code == 200:
				# Save the downloaded content to the specified file path
				with open(self.apkPath, "wb") as apkFile:
					apkFile.write(response.content)

				# Store the apkPath
				self.alreadyDownloaded = True
				print("--- 💾 APK file downloaded and saved to {}".format(self.apkPath))
				return
			else:
				print("--- ❌ Error: Received unexpected status code {}.".format(response.status_code))
				return
		
		print("--- ⚠️ [Error] Androzoo: Failed to download APK after {} attempts.".format(MAX_RETRIES))


	# Download app metadata from AndroZoo.
	def getAppMetadata(self):
		print("\n--- ⭕ [Running] Download Metadata from AZ.")

		MAX_RETRIES = 10
		RETRY_DELAY = 30  # Seconds

		# Load AndroZoo API KEY
		load_dotenv()
		apiKey 	= os.getenv("ANDROZOO_API_KEY")
		pkgName = self.pkgName

		baseUrl = 'https://androzoo.uni.lu/api/get_gp_metadata'
		url 	= "{}/{}".format(baseUrl, pkgName)
		params 	= {'apikey': apiKey}
		headers = {"User-Agent": "Wget/1.21.1 (linux-gnu)"}

		retries = 0
		while retries < MAX_RETRIES:
			print("--- 🔄 Attempt N: {}".format(retries + 1))
			try:
				response = requests.get(url, params=params, headers=headers, timeout=10)
			except requests.RequestException as e:
				print("--- ⚠️ [Error] Request failed: {}. Retrying in {} seconds...".format(e, RETRY_DELAY))
				retries += 1
				time.sleep(RETRY_DELAY)
				continue

			if response.status_code in [502, 503]:
				print("--- ⚠️ [Error] Androzoo: Received status code {}. Retrying in {} seconds...".format(response.status_code, RETRY_DELAY))
				retries += 1
				time.sleep(RETRY_DELAY)
			elif response.status_code == 200:
				print("--- ✅ [Success] Metadata downloaded for package: {}".format(pkgName))
				return response.json()
			else:
				print("--- ❌ Error: Received unexpected status code {}: {}".format(response.status_code, response.text))
				return None

		print("--- ⚠️ [Error] Androzoo: Failed to download metadata after {} attempts.".format(MAX_RETRIES))
		return None


	# Decompile the APK File using ApkTool.
	def decompileWithApkTool(self):
		try:
			# Command to decompile APK using ApkTool
			print("\n--- ⭕ [Running] ApkTool")

			outputFolder = self.apkPath[:-4]
			print("--- 📂 Output Folder: {}".format(outputFolder))

			# Run ApkTool
			command = ["apktool", "d", "-f", '-o', outputFolder, "-q", self.apkPath]
			subprocess.run(command, check=True)

			print("--- ✅ [Success] ApkTool")
			self.decompiledPath = outputFolder

		except subprocess.CalledProcessError as e:
			print("--- ⚠️ [Error] ApkTool: {}".format(e))
			raise

	# Analyze the APK File using Androguard.
	def analyseWithAndroguard(self):
		try:
			# Running Androguard
			print("\n--- ⭕ [Running] Androguard")

			# Perform the Analysis
			self.app_A, self.app_D, self.app_X = AnalyzeAPK(self.apkPath)
			print("--- ✅ [Success] Androguard")

			# Return Results
			return self.app_A, self.app_D, self.app_X

		except Exception as e:
			print("--- ⚠️ [Error] Androguard: {}".format(e))
			raise

	####################################

	### CLEANUP FUNCTIONS ###
	# Delete the APK file.
	def deleteAPK(self):
		try:
			print("--- 🗑️ Deleting APK File")
			os.remove(self.apkPath)
		except OSError as e:
			print("--- ⚠️ [Error] Deleting : {}\n".format(e))

	# Delete everything related to the analyzed app.
	def deleteAll(self):
		try:
			print("--- 🗑️ Deleting Folders")
			shutil.rmtree(self.apkPath[:-4])

			#print("--- 🗑️ Deleting Features File")
			#os.remove(self.apkPath[:-4] + "_features.json")
		except OSError as e:
			print("--- ⚠️ [Error] Deleting: {}".format(e))

	####################################
	### EXTRACTION FUNCTIONS ### 

	# Helper function to extract features for an app
	def extractAllFeatures(self):
		# To store the features
		features = {}

		# Extracting Certificates
		print("--- ⛏️ Extracting --> Certificates")
		features['certificates'] = self.extractCertificates()

		# Extracting Permissions
		print("--- ⛏️ Extracting --> Permissions")
		features['permissions'] = self.extractPermissions()

		# Extracting Components
		print("--- ⛏️ Extracting --> Components")
		features['components'] = self.extractAppComponents()

		# Extracting Files
		print("--- ⛏️ Extracting --> Files")
		features['files'] = self.extractFiles()

		# Extracting Smali Files
		print("--- ⛏️ Extracting --> Smali Files")
		features['smaliFiles'] = self.extractSmaliFiles()

		# Extracting Native Libraries
		print("--- ⛏️ Extracting --> Native Libraries")
		features['nativeLibs'] = self.extractNativeLibraries()

		# Extracting Third-Party Libraries
		print("--- ⛏️ Extracting --> Third-Party Libraries")
		features['thirdPartyLibs'] = self.extractThirdPartyLibraries()

		# Extracting URLs
		print("--- ⛏️ Extracting --> URLs")
		features['URLs'] = self.extractURLs()

		# Store the features
		self.features = features

		# Return the features
		return features

	# Extract permissions from the APK.
	def extractPermissions(self):
		if self.app_A is None:
			raise ValueError("--- APK has not been analyzed yet. Please run analyseWithAndroguard() first.")
		
		# Extract Permissions from Androguard Analysis
		permissions = set(self.app_A.get_permissions())
		return permissions
	
	# Extract components from the APK.
	def extractAppComponents(self):
		if self.app_A is None:
			raise ValueError("--- APK has not been analyzed yet. Please run analyseWithAndroguard() first.")
		
		# Extract Components from Androguard Analysis
		components = {
			'activities': set(self.app_A.get_activities()),
			'services'  : set(self.app_A.get_services()),
			'receivers' : set(self.app_A.get_receivers()),
			'providers' : set(self.app_A.get_providers())
		}
		return components
	
	# Extract files from the APK.
	def extractFiles(self):
		# # OPTION A: AndroGuard
		# if self.app_A is None:
		# 	raise ValueError("--- APK has not been analyzed yet. Please run analyseWithAndroguard() first.")
		# # Extract Files from Androguard Analysis
		# files = set(self.app_A.get_files())

		# OPTION B: ApkTool
		files = getFilesFromDirectory(self.decompiledPath)
		# Remove all files ending with ".smali"
		files = {file for file in files if not file.endswith(".smali")}
		# Exclude specific files
		files.discard("apktool.yml")

		# Remove non-existing files from the set
		nonExistingFiles = set()
		for file in files:
			filePath = os.path.join(self.decompiledPath, file)
			if not os.path.exists(filePath):
				nonExistingFiles.add(file)
		files -= nonExistingFiles

		# # TESTING PURPOSES
		# # Print the number and percentage of non-existing files
		# totalFiles = len(files) + len(nonExistingFiles)
		# if totalFiles > 0:
		# 	percentage = (len(nonExistingFiles) / totalFiles) * 100
		# 	print("--- 📊 Non-existing files: {} ({:.2f}%)".format(len(nonExistingFiles), percentage))
		# else:
		# 	print("--- 📊 No files to check.")

		return files
	
	# Extract smali files from the decompiled APK.
	def extractSmaliFiles(self):
		# Get all files with the .smali extension
		smaliFiles = getFilesFromDirectory(self.decompiledPath, ".smali")

		# Remove non-existing smali files from the set
		nonExistingSmaliFiles = set()
		for file in smaliFiles:
			filePath = os.path.join(self.decompiledPath, file)
			if not os.path.exists(filePath):
				nonExistingSmaliFiles.add(file)
		smaliFiles -= nonExistingSmaliFiles

		# # TESTING PURPOSES
		# # Print the number and percentage of non-existing smali files
		# totalSmaliFiles = len(smaliFiles) + len(nonExistingSmaliFiles)
		# if totalSmaliFiles > 0:
		# 	percentage = (len(nonExistingSmaliFiles) / totalSmaliFiles) * 100
		# 	print("--- 📊 Non-existing smali files: {} ({:.2f}%)".format(len(nonExistingSmaliFiles), percentage))
		# else:
		# 	print("--- 📊 No smali files to check.")

		return smaliFiles

	# Extract certificates from the APK.
	def extractCertificates(self):
		if self.app_A is None:
			raise ValueError("--- APK has not been analyzed yet. Please run analyseWithAndroguard() first.")
		
		# Extract Certificates from Androguard Analysis
		certificates = set(self.app_A.get_certificates())
		
		# Parse and return the certificates
		parsedCertificates = []

		for cert in certificates:
			# Load the certificate and extract the relevant information
			parsedCert = Certificate.load(cert.dump())
			certInfo = {
				'serialNumber'       : parsedCert.serial_number,
				'subject'            : parsedCert.subject.native,
				'issuer'             : parsedCert.issuer.native,
				'notValidBefore'     : parsedCert['tbs_certificate']['validity']['not_before'].native.isoformat(),
				'notValidAfter'      : parsedCert['tbs_certificate']['validity']['not_after'].native.isoformat(),
				'version'            : parsedCert['tbs_certificate']['version'].native,
				'signatureAlgorithm' : parsedCert['signature_algorithm'].native,
				'publicKey'          : parsedCert.public_key.native
			}
			parsedCertificates.append(certInfo)
		
		return parsedCertificates
	
	# Extract native libraries from the APK.
	def extractNativeLibraries(self):
		print("--- ⭕ [Running] Native Libs Extraction")
		if self.decompiledPath is None:
			raise ValueError("--- APK has not been decompiled yet. Please run decompileWithApkTool() first.")
			
		# Get the path to the lib directory
		libPath = os.path.join(self.decompiledPath, 'lib')
			
		# Get all .so files in the lib directory
		soFiles = getFilesFromDirectory(libPath, ".so")
		return soFiles
	
	# Extract Third Party Libraries from the APK.	
	def extractThirdPartyLibraries(self):
		print("--- ⭕ [Running] Libs Extraction")

		if self.decompiledPath is None:
			raise ValueError("--- APK has not been decompiled yet. Please run decompileWithApkTool() first.")
			
		# Get all smali files from the decompiled APK
		smaliFiles = getFilesFromDirectory(self.decompiledPath, ".smali")

		# Extract class names from smali files
		classes = set()
		for file in smaliFiles:
			with open(os.path.join(self.decompiledPath, file), 'r') as f:
				className = extractClassNameFromSmali(f.read())
				if className:
					classes.add(className)

		# Identify third-party libraries
		thirdPartyLibraries = identifyThirdPartyLibraries(classes)
		return thirdPartyLibraries

	# Extract URLs from the APK.
	def extractURLs(self):
		print("--- ⭕ [Running] URLs Extraction")
		if self.decompiledPath is None:
			raise ValueError("--- APK has not been decompiled yet. Please run decompileWithApkTool() first.")
			
		# Extract URLs from the decompiled APK
		urls = extractURLsFromFiles(self.decompiledPath)
		return urls


######################################################################

### UTILS ###
# Function to get files from a directory with an optional extension filter
def getFilesFromDirectory(dirPath, extension=None):
	files = set()
	for root, _, filenames in os.walk(dirPath):
		for filename in filenames:
			if extension is None or filename.endswith(extension):
				files.add(os.path.relpath(os.path.join(root, filename), dirPath))
	return files

# Extract Class Name from Smali Code Content
def extractClassNameFromSmali(text):
	# Use regex to match and capture the class name
	regex = r'\.class(?:\s+[\w\s]+)*\s+L([^;]+)'
	match = re.search(regex, text)
	if match:
		className = match.group(1).replace('/', '.')
		return className
	else:
		return None
	
# Identify third party libraries using a list of libs
def identifyThirdPartyLibraries(classes):
	# Get the path to the file from .env
	thirdPartyLibsPath = os.getenv('THIRD_PARTY_LIBS_PATH')
	
	# Read third-party libraries from file
	with open(thirdPartyLibsPath, 'r') as f:
		thirdPartyLibs = {line.strip() for line in f}
		# Test
		#print("------ #️⃣ Number of third-party libraries available: {}".format(len(thirdPartyLibs)))
	
	# Check in class Names
	thirdPartyClasses = {lib for lib in thirdPartyLibs if any(cls.startswith(lib) for cls in classes)}
	
	return thirdPartyClasses

# Function to extract URLs from files in a given directory
def extractURLsFromFiles(dirPath):
	urls = set()
	regex = re.compile(r'https?://[^\s/$.?#].[^\s]*')
	for root, _, filenames in os.walk(dirPath):
		for filename in filenames:
			filePath = os.path.join(root, filename)
			with open(filePath, 'r', errors='ignore') as file:
				content = file.read()
				foundUrls = regex.findall(content)
				# for url in foundUrls:
				# 	urls.add()
				for url in foundUrls:
						# Remove null bytes
						cleanedUrl = url.replace('\x00', '').replace('%s', '')

						try:
							# Parse URL
							parsedUrl = urllib.parse.urlparse(cleanedUrl)

							# Rebuild URL, ensuring a proper scheme exists
							if not parsedUrl.scheme or not parsedUrl.netloc:
								continue  # Skip malformed URLs
												
							parsedUrl = parsedUrl._replace(fragment='')

							# Construct a valid URL
							validUrl = urllib.parse.urlunparse(parsedUrl)
							urls.add(validUrl)
							
						except Exception as e:
							print("--- ⚠️ [Warning] Error processing URL: {}. Error: {}".format(cleanedUrl, e))

	# Filter URLs to keep only first level
	filteredUrls = set()
	for url in urls:
		parts = url.split('/')
		# To avoid strange URLs
		if len(parts) > 2:
			if len(parts[2])>2:
				filteredUrls.add('/'.join(parts[:3]))
		else:
			filteredUrls.add(url)

	urls = filteredUrls
	return urls