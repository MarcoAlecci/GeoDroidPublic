<div align="center"> 
  
  <h1>GeoTwins: Uncovering Hidden Geographic Disparities in Android Apps</h1> 

  <p align="center"> In this repository, we host all the data and code related to our paper titled "GeoTwins: Uncovering Hidden Geographic Disparities in Android Apps". </p>
</div>

## 📜 Abstract

>While mobile app evolution over time has been extensively studied, geographical variation in app behavior remains largely unexplored. This paper presents the first large-scale study of location-based Android app differentiation, revealing two critical and previously unknown phenomena with significant security and policy implications. First, we introduce the concept of GeoTwins: apps that are functionally similar and share branding, yet are released under different package names (i.e., as two separate apps) in different countries. Despite their apparent similarity, GeoTwins often diverge in critical aspects such as requested permissions, third-party libraries, and privacy disclosures. For example, we found that the Japanese version of the game Unison League requests the ACCESS_FINE_LOCATION permission, whereas its international counterpart does not, even though both share the same branding and user interface. Second, we investigate the Android App Bundle ecosystem and uncover unexpected regional differences in the supposedly consistent base.apk files, which are generally assumed to be invariant. Contrary to expectations, our analysis shows that even base.apk files can vary by region, revealing hidden customizations that may affect app behavior or security. The discrepancies observed through these two phenomena raise concerns about potential digital inequality, where users in different regions experience varying levels of access to features, privacy protection, or security standards. To support our study, we developed a distributed app collection pipeline spanning multiple regions and analyzed thousands of apps. We also release our dataset of 81 963 GeoTwins to facilitate further research. Our findings reveal systemic regional disparities in mobile software, with critical implications for app developers (who must consider regional compliance and user expectations), platform architects (who must address distribution inconsistencies), and policymakers (focused on digital fairness and global user protection).

### 🗂️ Repository Organization

The repository is organized into main directories:

* **📁 0_Data**  

  This directory contains all the data related to our experiments.

* **📂 1_Code**  
  Contains all the code relative to our experiments. The code is provided into the form of multiple Jupyter Notebooks to facilitate execution.

### 📋 Requirements

#### 🐍 Conda Environment

To launch the Jupyter Notebook, you will need various libraries. We provide a **requirements.txt** file which you can use to create a conda environment.

Follow the steps below:

1. **Create a conda environment named `demoEnv`:**

    ```bash
    conda create --name demoEnv python=3.8
    ```

2. **Activate the newly created environment:**

    ```bash
    conda activate demoEnv
    ```

3. **Install the required packages using `pip` and `requirements.txt`:**

    ```bash
    pip install -r requirements.txt
    ```

Once these steps are complete, your environment will be set up with all the necessary libraries.

#### 🔧 ApkTool
To decompile APKs, **ApkTool** must be installed on your system. Follow the steps below to set it up:

1. **Download ApkTool:**  
   Visit the official ApkTool page at [https://ibotpeaches.github.io/Apktool/](https://ibotpeaches.github.io/Apktool/) and download the latest version.

2. **Install ApkTool:**  
   Follow the installation instructions for your operating system, which typically involve:

   - Placing the downloaded JAR file in a suitable directory.
   - Adding the ApkTool executable to your system's PATH for easier access.

3. **Verify Installation:**  
   Ensure ApkTool is installed correctly by running the following command in your terminal:

    ```bash
    apktool
    ```

   This should display the ApkTool usage instructions if the installation was successful.

#### 📌 Environment File (.env)

Some settings should be specified in an environment file named `.env`, which should be placed in the main folder of this repository.

##### 🔑 AndroZoo API Key
To analyze APKs, you need access to [AndroZoo](https://androzoo.uni.lu/). 

**`ANDROZOO_API_KEY`**: This key is necessary to download apps from the *AndroZoo* Repository, as various operations on the APK files are performed "on-the-fly," such as app download, extraction, and deletion. It can be requested here: <https://androzoo.uni.lu/access>

Example `.env` entry for the AndroZoo API Key:
```
ANDROZOO_API_KEY = [YOUR_ANDROZOO_API_KEY]
```

##### 📚 Third-Party Libraries Path

During APK analysis, the tool compares against a list of known third-party libraries. You must provide the path to this file in your `.env`.

**`THIRD_PARTY_LIBS_PATH`**: This specifies the path to the list of known third-party libraries used during the analysis of the APKs. The list can be obtained from: [https://github.com/JordanSamhi/AndroLibZoo](https://github.com/JordanSamhi/AndroLibZoo)

Example `.env` entry for the third-party libraries path:
```
THIRD_PARTY_LIBS_PATH = [YOUR_PATH_TO_THETHIRD_PARTY_LIBS_FILE]
```

### ⚙️ Usage

The provided Jupyter Notebooks facilitates the experiments.

TODO