# Android Analyzer

## Overview
Android Analyzer is a machine learning-based application designed to classify Android APK files as **Suspicious** (malicious) or **Benign** (safe) based on their feature signatures. The project leverages machine learning techniques to identify potentially harmful apps efficiently.

## Datasets
The project uses datasets from [Android Malware Dataset for Machine Learning](https://www.kaggle.com/datasets/shashwatwork/android-malware-dataset-for-machine-learning):
1. **First Dataset**: This dataset contains **15,036 APK samples** categorized as **9476 benign** and **5560 suspicious**, with 215 features representing various API call behaviors.
2. **Second Dataset**: This dataset maps the feature names from the first(main) dataset to their corresponding API call signatures, providing better interpretability and understanding of the features used in classification.

## Components
### analyzer.ipynb
This notebook handles the loading and preprocessing of the first(main) dataset. Three models were trained:
- **Random Forest Classifier**
- **Logistic Regression**
- **Decision Tree**

The Random Forest Classifier achieved the highest accuracy among the models and was saved as `rf_classifier.pkl` using `joblib` for use in the application.

### main.py
This script uses the trained Random Forest Classifier to classify two example APKs based on their feature sets:
1. A **Suspicious APK** containing features indicative of malicious behavior.
2. A **Benign APK** with features representative of safe and harmless behavior.

The script loads the pre-trained model and processes the feature sets using `numpy` arrays. Predictions are displayed in a human-readable format, indicating whether an APK is classified as "Suspicious" or "Benign."

### features.ipynb
This notebook visualizes the feature descriptions dataset to provide insights into the distribution of features across API call signature categories. A bar chart is generated to show the count of features within each category, highlighting the significance of features in the classification process.

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
4. Run `main.py` to classify sample APKs:
   ```bash
   python main.py
   ```
> **Note**: Retraining the model is not required as the pre-trained `rf_classifier.pkl` is included in the repository.

## Dataset Link
- [Android Malware Dataset for Machine Learning](https://www.kaggle.com/datasets/shashwatwork/android-malware-dataset-for-machine-learning)

## Author
Developed by **Abu Huraira Zaheer**.  
[LinkedIn Profile](https://www.linkedin.com/in/hurairaz/)


