package com.notjuststudio.secretingredient;

import com.sun.istack.internal.NotNull;

public class GeneratingKeyException extends RuntimeException {

    public GeneratingKeyException() {
        super();
    }

    public GeneratingKeyException(@NotNull final String message) {
        super(message);
    }

    public GeneratingKeyException(@NotNull final Throwable cause) {
        super(cause);
    }
}
