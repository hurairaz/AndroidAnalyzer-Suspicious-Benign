# Android Analyzer

## Overview
Android Analyzer is a machine learning-based application designed to classify Android APK files as **Suspicious** (malicious) or **Benign** (safe) based on their feature signatures. The project leverages machine learning techniques to identify potentially harmful apps efficiently. The project also incorporates `Androguard` to extract permissions, API calls, and intents from APK files.

## Datasets
The project uses datasets from [Android Malware Dataset for Machine Learning](https://www.kaggle.com/datasets/shashwatwork/android-malware-dataset-for-machine-learning):
1. **First Dataset**: Contains **15,036 APK samples** categorized as **9476 benign** and **5560 suspicious**, with 215 features representing various API call behaviors.
2. **Second Dataset**: Maps feature names from the first (main) dataset to their corresponding API call signatures, providing better interpretability and understanding of the features used in classification.

## Components
### `model_training.ipynb`
This notebook handles the loading and preprocessing of the main dataset. Three models were trained:
- **Random Forest Classifier**
- **Logistic Regression**
- **Decision Tree**

The Random Forest Classifier achieved the highest accuracy and was saved as `rf_classifier.pkl` using `joblib` for later use in the application.

### `main.py`
This script uses the trained Random Forest Classifier to classify APK files. It first extracts features such as permissions, API calls, and intents from an APK file using `Androguard`. These features are then matched against the predefined 215 feature set to generate a binary vector, which is used for prediction. 

Due to its size, `whatsapp.apk` could not be included in the repository. However, you can place your own APK file (e.g., `my_app.apk`) in the root directory for analysis. The result will indicate whether the APK is classified as **Suspicious** or **Benign**.

### `features.ipynb`
This notebook visualizes the feature descriptions dataset, providing insights into the distribution of features across API call signature categories. A bar chart is generated to show the count of features within each category, highlighting their significance in the classification process.

## How to Use
1. Clone the repository:
   ```bash
   git clone https://github.com/hurairaz/AndroidAnalyzer-Suspicious-Benign.git
   cd AndroidAnalyzer-Suspicious-Benign
   ```
2. Create and activate a virtual environment:
   - On **Windows**:
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```
   - On **macOS/Linux**:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Place your APK file (e.g., `my_app.apk`) in the root directory and update the apk_path in the `main.py` file.
5. Run the `main.py` script:
   ```bash
   python main.py
   ```

## Dataset Link
- [Android Malware Dataset for Machine Learning](https://www.kaggle.com/datasets/shashwatwork/android-malware-dataset-for-machine-learning)

## Author
Developed by **Abu Huraira Zaheer, Haris Humayon, and Abdullah Javeed**.  
[LinkedIn Profile](https://www.linkedin.com/in/hurairaz/)

