import sqlite3


def create_database():

    connection = sqlite3.connect("phishguard.db")
    cursor = connection.cursor()
    columns = [
        ("body", "TEXT"),
        ("urls", "TEXT"),
        ("keywords", "TEXT"),
        ("url_warnings", "TEXT"),
        ("sender_warnings", "TEXT"),
        ("reply_warnings", "TEXT"),
        ("auth_checks", "TEXT")
    ]

    for column, data_type in columns:
        try:
            cursor.execute(
                f"ALTER TABLE email_history ADD COLUMN {column} {data_type}"
            )
        except sqlite3.OperationalError:
            pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            subject TEXT,
            risk_score INTEGER,
            verdict TEXT,
            body TEXT,
            urls TEXT,
            keywords TEXT,
            url_warnings TEXT,
            sender_warnings TEXT,
            reply_warnings TEXT,
            auth_checks TEXT,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


def save_email(
    sender,
    subject,
    risk_score,
    verdict,
    body,
    urls,
    keywords,
    url_warnings,
    sender_warnings,
    reply_warnings,
    auth_checks
):

    connection = sqlite3.connect("phishguard.db")
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO email_history
        (
            sender,
            subject,
            risk_score,
            verdict,
            body,
            urls,
            keywords,
            url_warnings,
            sender_warnings,
            reply_warnings,
            auth_checks
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        sender,
        subject,
        risk_score,
        verdict,
        body,
        "\n".join(urls),
        "\n".join(keywords),
        "\n".join(url_warnings),
        "\n".join(sender_warnings),
        "\n".join(reply_warnings),
        "\n".join(auth_checks)
    ))

    connection.commit()
    connection.close()


if __name__ == "__main__":
    create_database()
    print("PhishGuard database created successfully!")
