# 📊 Netsuite-Cribl

A Python-based integration tool designed to bridge data between NetSuite and Cribl, facilitating streamlined data workflows and enhanced analytics capabilities.

---

## 🚀 Features

- 🔗 **NetSuite Integration** – Connects to NetSuite to retrieve and process data.
- 📤 **Cribl Compatibility** – Formats and sends data to Cribl for further processing.
- 🧩 **Modular Design** – Easily extendable to accommodate additional data sources or destinations.

---

## 📦 Prerequisites

- 🐍 Python 3.8 or higher
- 🔐 NetSuite account with API credentials
- 💾 Cribl instance that accepts HTTP input

---

## 🛠️ Installation

1. **Clone the repository**:

    ```bash
    git clone https://github.com/dobyfreejr/Netsuite-Cribl.git
    cd Netsuite-Cribl
    ```

2. **(Optional) Create and activate a virtual environment**:

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3. **Install required dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

---

## ⚙️ Configuration

Create a `.env` file in the project root with the following variables:

```env
NETSUITE_ACCOUNT=your_netsuite_account_id
NETSUITE_CONSUMER_KEY=your_consumer_key
NETSUITE_CONSUMER_SECRET=your_consumer_secret
NETSUITE_TOKEN_KEY=your_token_key
NETSUITE_TOKEN_SECRET=your_token_secret
CRIBL_ENDPOINT=your_cribl_endpoint_url
```

> 🔒 **Note:** Do **not** commit your `.env` file. Be sure to add `.env` to your `.gitignore`.

---

## ▶️ Usage

Run the script:

```bash
python netsuites.py
```

This will authenticate with NetSuite, retrieve the necessary data, and forward it to Cribl.


---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. 🍴 Fork the repository
2. 📂 Create a new branch:

    ```bash
    git checkout -b feature/your-feature-name
    ```

3. 💾 Commit your changes:

    ```bash
    git commit -m "Add your message"
    ```

4. 📤 Push to your fork:

    ```bash
    git push origin feature/your-feature-name
    ```

5. 📝 Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 📬 Contact

Created by [@dobyfreejr](https://github.com/dobyfreejr) – feel free to reach out with questions, feedback, or ideas!
