/* See LICENSE.md for license information */
package org.ice4j.ice;

/**
 * Ever CheckList is associated with a state, which captures the state of ICE checks for that media stream. There are three states:
 * <br>
 * Running:  In this state, ICE checks are still in progress for this media stream.
 * <br>
 * Completed:  In this state, ICE checks have produced nominated pairs for each component of the media stream.  Consequently, ICE has succeeded and
 * media can be sent.
 * <br>
 * Failed:  In this state, the ICE checks have not completed successfully for this media stream.
 * <br>
 * When a check list is first constructed as the consequence of an offer/answer exchange, it is placed in the Running state.
 *
 * @author Emil Ivov
 */
public enum CheckListState {
    /**
     * In this state, ICE checks are still in progress for this media stream.
     */
    RUNNING("Running"),

    /**
     * In this state, ICE checks have produced nominated pairs for each component of the media stream.  Consequently, ICE has succeeded and
     * media can be sent.
     */
    COMPLETED("Completed"),

    /**
     * In this state, the ICE checks have not completed successfully for this media stream.
     */
    FAILED("Failed");

    /**
     * The name of this CheckListState instance.
     */
    private final String stateName;

    /**
     * Creates a CheckListState instance with the specified name.
     *
     * @param stateName the name of the CheckListState instance we'd like to create
     */
    private CheckListState(String stateName) {
        this.stateName = stateName;
    }

    /**
     * Returns the name of this CheckListState (i.e.. "Running", "Completed", or "Failed").
     *
     * @return the name of this CheckListState
     */
    @Override
    public String toString() {
        return stateName;
    }
}
