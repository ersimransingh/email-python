"""
PDF utilities for password protection and manipulation
"""

import io
from typing import Optional
from pypdf import PdfReader, PdfWriter


class PDFPasswordProtector:
    """Utility class for PDF password protection"""

    @staticmethod
    def protect_pdf_with_password(pdf_data: bytes, password: str) -> bytes:
        """
        Protect a PDF with a password

        Args:
            pdf_data: Original PDF as bytes
            password: Password to protect the PDF

        Returns:
            Password-protected PDF as bytes
        """
        try:
            print(f"Protecting PDF with password (length: {len(password)})")

            # Create a PDF reader from the original data
            pdf_reader = PdfReader(io.BytesIO(pdf_data))

            # Create a PDF writer
            pdf_writer = PdfWriter()

            # Copy all pages from reader to writer
            for page in pdf_reader.pages:
                pdf_writer.add_page(page)

            # Encrypt the PDF with password
            pdf_writer.encrypt(password)

            # Save to bytes
            output_buffer = io.BytesIO()
            pdf_writer.write(output_buffer)
            protected_pdf_data = output_buffer.getvalue()

            print(f"PDF protected successfully. Original size: {len(pdf_data)} bytes, Protected size: {len(protected_pdf_data)} bytes")

            return protected_pdf_data

        except Exception as e:
            print(f"Error protecting PDF with password: {e}")
            raise Exception(f"Failed to protect PDF: {str(e)}")

    @staticmethod
    def verify_pdf_protection(pdf_data: bytes, password: str) -> bool:
        """
        Verify that a PDF is properly password protected

        Args:
            pdf_data: Password-protected PDF as bytes
            password: Password used to protect the PDF

        Returns:
            True if PDF is properly protected and can be opened with password
        """
        try:
            # Try to read the PDF with the password
            pdf_reader = PdfReader(io.BytesIO(pdf_data))

            if pdf_reader.is_encrypted:
                # Try to decrypt with the password
                if pdf_reader.decrypt(password):
                    print("PDF verification successful - properly protected and accessible with password")
                    return True
                else:
                    print("PDF verification failed - cannot decrypt with provided password")
                    return False
            else:
                print("PDF verification failed - PDF is not encrypted")
                return False

        except Exception as e:
            print(f"Error verifying PDF protection: {e}")
            return False

    @staticmethod
    def is_pdf_data(data: bytes) -> bool:
        """
        Check if the data is a valid PDF

        Args:
            data: Data to check

        Returns:
            True if data appears to be a PDF
        """
        try:
            # Check PDF magic header
            if data.startswith(b'%PDF-'):
                return True
            return False
        except Exception:
            return False

    @staticmethod
    def get_pdf_info(pdf_data: bytes) -> dict:
        """
        Get basic information about a PDF

        Args:
            pdf_data: PDF as bytes

        Returns:
            Dictionary with PDF information
        """
        try:
            pdf_reader = PdfReader(io.BytesIO(pdf_data))

            info = {
                "num_pages": len(pdf_reader.pages),
                "is_encrypted": pdf_reader.is_encrypted,
                "size_bytes": len(pdf_data),
                "has_metadata": pdf_reader.metadata is not None
            }

            if pdf_reader.metadata:
                info["title"] = pdf_reader.metadata.get("/Title", "")
                info["author"] = pdf_reader.metadata.get("/Author", "")
                info["creator"] = pdf_reader.metadata.get("/Creator", "")

            return info

        except Exception as e:
            return {"error": str(e)}