import ast

# Prepocess the dataset to clean and filter the data
def preprocessDataset(appsDF):
	# Get the list of locations from the columns
	locationsList = appsDF.columns[2:].to_list()
	print("--- 🌍 Locations [{}]: {}\n".format(len(locationsList),locationsList))

	# Apply ast.literal_eval to every column except the first one
	for col in appsDF.columns[2:]:
		appsDF[col] = appsDF[col].apply(lambda x: ast.literal_eval(x) if isinstance(x, str) else x)

	# Replace '404' string with 404 number
	appsDF.replace('404', 404, inplace=True)

	# Count the number of rows where at least one column (except the first) has a '404' value
	numAtLeastOne404 = (appsDF.iloc[:, 2:] == 404).any(axis=1).sum()

	# Count the number of rows where all columns (except the first) are equal to False
	numAllFalse = (appsDF.iloc[:, 2:] == False).all(axis=1).sum()

	# Count the number of rows where all columns (except the first) are equal to True
	numAllTrue = (appsDF.iloc[:, 2:] == True).all(axis=1).sum()

	# Print the numbers in a nicely formatted way with emoji
	print("--- ✅ Number of apps with all location are True : {}".format(numAllTrue))
	print("--- ❌ Number of apps with all location are False: {}".format(numAllFalse))
	print("--- ⚠️ Number of apps with at least one 404      : {}".format(numAtLeastOne404))

	# Remove rows with all locations as False
	appsDF = appsDF[(appsDF.iloc[:, 2:] != False).any(axis=1)]

	# Remove rows with at least one 404
	appsDF = appsDF[~(appsDF.iloc[:, 2:] == 404).any(axis=1)]

	# Save allTrueDF
	allTrueDF = appsDF[(appsDF.iloc[:, 2:] == True).all(axis=1)]

	# Remove rows with all locations as True
	appsDF = appsDF[~(appsDF.iloc[:, 2:] == True).all(axis=1)]

	# Print the number of remaining apps
	print("--- #️⃣ Number of remaining apps                  : {}".format(appsDF.shape[0]))

	return locationsList, appsDF, allTrueDF

# Get apps that can be downloaded in only one location
def getAppsPerLocation(appsDF, locationsList):
	# Get apps that can be downloaded in only one location
	dfsPerLocation = {}

	for location in locationsList:
		if location in appsDF.columns:
			# Create a dataframe where the location is True and all other locations are False
			df = appsDF[(appsDF[location] == True) & (appsDF[locationsList].sum(axis=1) == 1)]
			# Keep only sha256 and pkgName columns
			df = df[['sha256', 'pkgName']]
			dfsPerLocation[location] = df

	for location, df in dfsPerLocation.items():
		print("--- 📍 {:<12}: {:<5} Unique Pkg Names".format(location, df.shape[0]))

	return dfsPerLocation