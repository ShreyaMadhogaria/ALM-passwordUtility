package com.wiley.bir.exception;

public class EncryptionException extends Exception {

    private static final long serialVersionUID = 1L;
    private final String message;

    public EncryptionException(final String message) {
        super(message);
        this.message = message;
    }

    @Override
    public String getMessage() {
        return this.message;
    }
}
