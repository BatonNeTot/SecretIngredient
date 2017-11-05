package com.notjuststudio.secretingredient;

import com.sun.istack.internal.NotNull;

public class CryptographicException extends RuntimeException {

    public CryptographicException() {
        super();
    }

    public CryptographicException(@NotNull final String message) {
        super(message);
    }

    public CryptographicException(@NotNull final Throwable cause) {
        super(cause);
    }
}
