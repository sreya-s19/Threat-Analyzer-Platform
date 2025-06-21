# Threat Analyzer Platform 🛡️

An integrated, multi-page application for real-time cybersecurity threat detection and interactive intelligence dashboarding. Built with Python, Streamlit, Pandas, and spaCy.

![alt text](https://i.imgur.com/6jr251O.png)

![alt text](https://i.imgur.com/Z3qwbq0.png)

![alt text](https://i.imgur.com/f8WtBaO.png)

---

## 📖 Overview

This project is a sophisticated, full-stack cybersecurity tool that combines two critical functions into a single, seamless platform:

1.  **Real-Time Detection:** A user-facing tool to analyze individual emails or messages for signs of phishing and social engineering on the fly.
2.  **Intelligence Dashboard:** A strategic dashboard that aggregates and visualizes all historical analysis data, allowing for the identification of attack trends and patterns.

Unlike traditional filters, this platform analyzes communications across multiple vectors—linguistic, structural, and technical—to provide a holistic risk assessment. Every analysis performed in the real-time tool automatically contributes to the historical dataset, making the intelligence dashboard richer with every use.

---

## ✨ Key Features

### Real-Time Detector Page
*   **Instant Analysis:** Paste any text-based message for an immediate threat assessment.
*   **Detailed Findings:** Provides a breakdown of all detected suspicious indicators.
*   **Automatic Data Logging:** Every analysis is automatically saved to a persistent SQLite database, feeding the intelligence dashboard.

### Intelligence Dashboard Page
*   **High-Level KPIs:** View key metrics at a glance, such as Total Messages Analyzed, Average Threat Score, and the Percentage of High-Risk Threats.
*   **Dynamic Visualizations:**
    *   **Top Threat Types:** A bar chart showing the most frequently used attack tactics.
    *   **Threats Over Time:** A line chart visualizing the volume of threats detected per day.
*   **Interactive Filtering:** Dynamically filter the entire dashboard by date range and threat score to drill down into specific data points.
*   **Data Explorer:** An interactive table displaying the full, filtered dataset for detailed review.

---

## 🛠️ Tech Stack & Architecture

This project is built as a unified Streamlit application, eliminating the need for a separate backend API and simplifying the architecture.

*   **Application Framework:** Streamlit
*   **Language:** Python 3.9+
*   **Data Processing & Analysis:** Pandas
*   **Natural Language Processing (NLP):** spaCy
*   **Domain Reputation:** python-whois
*   **Database:** SQLite
*   **Version Control:** Git & GitHub

---

## 🚀 How to Run This Project Locally

### Prerequisites
*   Python 3.8+
*   Git

### Setup Instructions

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/Threat-Analyzer-Platform.git
    cd Threat-Analyzer-Platform
    ```
    *(Replace `your-username` with your actual GitHub username)*

2.  **Create and activate a virtual environment:**
    ```bash
    # Create the environment
    python -m venv venv

    # Activate on Windows
    .\venv\Scripts\activate

    # Activate on macOS/Linux
    source venv/bin/activate
    ```

3.  **Install the required dependencies:**
    This single command installs everything needed to run the project.
    ```bash
    pip install -r requirements.txt
    ```

4.  **Download the spaCy language model:**
    This is a one-time download for the NLP module.
    ```bash
    python -m spacy download en_core_web_sm
    ```

### Running the Application

1.  **Navigate to the project directory** in your terminal (with the virtual environment active).
2.  **Run the single command:**
    ```bash
    streamlit run app.py
    ```
3.  A new tab will automatically open in your web browser. Use the sidebar to navigate between the "Real-Time Detector" and the "Intelligence Dashboard" pages.

---

## 💡 Future Improvements

*   **Email Header Analysis:** Extend the analysis engine to parse raw `.eml` files and validate sender authenticity via SPF, DKIM, and DMARC.
*   **Advanced NLP:** Use more advanced NLP techniques like sentiment analysis and topic modeling to detect more nuanced threats.
*   **User Accounts:** Implement a user login system to create personalized dashboards.
*   **Deployment:** Deploy the application to Streamlit Community Cloud for public access.
