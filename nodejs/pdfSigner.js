const fs = require('fs');
const path = require('path');
const { plainAddPlaceholder } = require('@signpdf/placeholder-plain');
const { SignPdf } = require('@signpdf/signpdf');
const { PDFDocument } = require('pdf-lib');

/**
 * Digitally signs a PDF using a PKCS#12 certificate.
 *
 * This mirrors the Python implementation in `app/utils/pdf_signing.py`
 * by preparing the PDF (including decrypting password protected files),
 * adding a signature placeholder, and finally applying the CMS signature.
 *
 * @param {Object} params
 * @param {Buffer|string} params.pdfBuffer - Raw PDF bytes or a filesystem path.
 * @param {string} params.signerName - Name displayed in the signature metadata.
 * @param {string} [params.certificatePath] - Filesystem path to the `.p12` certificate.
 * @param {Buffer} [params.certificateBuffer] - Raw PKCS#12 certificate bytes.
 * @param {string} [params.certificatePassword] - Passphrase for the certificate (if required).
 * @param {string} [params.pdfPassword] - Password for opening the PDF before signing.
 * @param {string} [params.reason] - Reason shown in the signature metadata.
 * @param {string} [params.location] - Location shown in the signature metadata.
 * @param {string} [params.contactInfo] - Contact info shown in the signature metadata.
 * @param {number} [params.signatureLength=8192] - Reserve length for the CMS signature.
 * @returns {Promise<Object>} Result metadata and the signed PDF bytes.
 */
async function signPdfDocument(params) {
  const {
    pdfBuffer,
    signerName,
    certificatePath,
    certificateBuffer,
    certificatePassword,
    pdfPassword,
    reason,
    location,
    contactInfo,
    signatureLength = 8192,
  } = params || {};

  if (!pdfBuffer) {
    throw new Error('signPdfDocument: `pdfBuffer` is required.');
  }

  if (!signerName) {
    throw new Error('signPdfDocument: `signerName` is required.');
  }

  let pdfInputBuffer = pdfBuffer;
  if (typeof pdfInputBuffer === 'string') {
    const resolvedPdfPath = path.resolve(pdfInputBuffer);
    pdfInputBuffer = fs.readFileSync(resolvedPdfPath);
  }

  let pkcs12Buffer = certificateBuffer;
  if (!pkcs12Buffer && certificatePath) {
    const resolvedCertPath = path.resolve(certificatePath);
    pkcs12Buffer = fs.readFileSync(resolvedCertPath);
  }

  if (!pkcs12Buffer) {
    throw new Error('signPdfDocument: PKCS#12 certificate bytes are required.');
  }

  try {
    const prepared = await preparePdfForSigning(pdfInputBuffer, pdfPassword);
    const placeholder = addSignaturePlaceholder(prepared.pdfBuffer, {
      signerName,
      reason,
      location,
      contactInfo,
      signatureLength,
    });

    const signer = new SignPdf();
    const signedPdfBuffer = signer.sign(
      placeholder.pdfBuffer,
      pkcs12Buffer,
      certificatePassword ? { passphrase: certificatePassword } : undefined,
    );

    const signedAt = new Date();

    return {
      success: true,
      error: null,
      signedPdf: signedPdfBuffer,
      signedBy: signerName,
      signedOn: signedAt.toISOString().slice(0, 10), // YYYY-MM-DD
      signedTime: signedAt.toISOString().slice(11, 19), // HH:MM:SS
      encryptionReencrypted: false, // Node implementation does not re-apply encryption.
      metadata: {
        reason: placeholder.reason,
        location,
        contactInfo,
        certificateSource: certificatePath ? 'pkcs12-file' : 'pkcs12-buffer',
        pdfWasEncrypted: prepared.wasEncrypted,
      },
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      signedPdf: pdfInputBuffer,
      signedBy: signerName,
      signedOn: null,
      signedTime: null,
      encryptionReencrypted: false,
    };
  }
}

async function preparePdfForSigning(pdfBuffer, pdfPassword) {
  let wasEncrypted = false;

  // `node-signpdf` requires PDFs without object streams and without encryption.
  const decryptedDocument = await PDFDocument.load(pdfBuffer, pdfPassword ? { password: pdfPassword } : undefined);
  if (pdfPassword) {
    wasEncrypted = true;
  }

  const preparedPdf = await decryptedDocument.save({ useObjectStreams: false });
  return { pdfBuffer: Buffer.from(preparedPdf), wasEncrypted };
}

function addSignaturePlaceholder(pdfBuffer, options) {
  const {
    signerName,
    reason,
    location,
    contactInfo,
    signatureLength,
  } = options;

  const signatureReason = reason || `Digitally signed by ${signerName}`;

  const placeholderBuffer = plainAddPlaceholder({
    pdfBuffer,
    reason: signatureReason,
    contactInfo,
    name: signerName,
    location,
    signatureLength,
  });

  return {
    pdfBuffer: placeholderBuffer,
    reason: signatureReason,
  };
}

module.exports = {
  signPdfDocument,
};
