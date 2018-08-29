/* See LICENSE.md for license information */
package org.ice4j.attribute;

/**
 * An {@link IceControlAttribute} implementation representing the
 * ICE-CONTROLLING ICE {@link Attribute}s.
 */
public final class IceControllingAttribute extends IceControlAttribute {
    /**
     * Constructs an ICE-CONTROLLING attribute.
     */
    public IceControllingAttribute() {
        super(true);
    }

    @Override
    public String toString() {
        return "IceControllingAttribute [tieBreaker=" + tieBreaker + ", isControlling=" + isControlling + "]";
    }
}
