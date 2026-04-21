// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.resilientocsp.exceptions;

import eu.webeid.ocsp.exceptions.UserCertificateUnknownStatusException;
import eu.webeid.security.validator.ValidationInfo;

import java.net.URI;

/**
 * Thrown when an OCSP service returns the unknown status for the user certificate and the unknown status is final.
 */
public class ResilientUserCertificateUnknownStatusException extends UserCertificateUnknownStatusException {

    private ValidationInfo validationInfo;

    public ResilientUserCertificateUnknownStatusException(URI ocspResponderUri, ValidationInfo validationInfo) {
        super(ocspResponderUri);
        this.validationInfo = validationInfo;
    }

    public ValidationInfo getValidationInfo() {
        return validationInfo;
    }

    public void setValidationInfo(ValidationInfo validationInfo) {
        this.validationInfo = validationInfo;
    }
}
