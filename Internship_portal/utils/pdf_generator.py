from reportlab.pdfgen import canvas
import io

class PDFGenerator:
    @staticmethod
    def generate_certificate(student_name, course_name, date):
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer)
        c.drawString(100, 750, "Certificate of Completion")
        c.drawString(100, 700, f"This certifies that {student_name}")
        c.drawString(100, 650, f"Has completed the internship in {course_name}")
        c.drawString(100, 600, f"Date: {date}")
        c.save()
        buffer.seek(0)
        return buffer
