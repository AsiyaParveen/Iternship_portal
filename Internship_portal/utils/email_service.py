class EmailService:
    @staticmethod
    def send_email(to_email, subject, body):
        print(f"MOCK EMAIL TO: {to_email}\nSUBJECT: {subject}\nBODY: {body}")
        # In production, use Flask-Mail here
