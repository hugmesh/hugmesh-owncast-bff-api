package net.hugmesh.owncastbff;

import net.hugmesh.owncastbff.access.OwncastAccessDto;
import net.hugmesh.owncastbff.mod.OwncastModerationDto;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins the defensive-copy contract of the two records that carry a mutable {@link List}
 * ({@code OwncastAccessDto.AccessList}, {@code OwncastModerationDto.StreamList}), which is
 * what clears SpotBugs EI_EXPOSE_REP / EI_EXPOSE_REP2 for them:
 *
 * <ul>
 *   <li>the record keeps its OWN copy: a caller mutating the list it passed in later does
 *       not change the record;</li>
 *   <li>the accessor never hands out a mutable list;</li>
 *   <li>{@code null} stays {@code null} and {@code null} elements are tolerated — a
 *       malformed payload must not turn into an NPE (and so a 500), which is exactly what
 *       {@code List.copyOf} would do and why it is not used here.</li>
 * </ul>
 *
 * <p>The JSON wire shape is unchanged and stays covered by the controller and full-chain
 * tests ({@code $.access[...]}, {@code $.streams[...]}) and the committed-OpenAPI drift guard.
 */
class ListCarrierDefensiveCopyTest {

    @Test
    void accessListKeepsItsOwnReadOnlyCopy() {
        assertListContract(src -> new OwncastAccessDto.AccessList(src)::access, access("a1"), access("a2"));
    }

    @Test
    void streamListKeepsItsOwnReadOnlyCopy() {
        assertListContract(src -> new OwncastModerationDto.StreamList(src)::streams, streamRow("s1"), streamRow("s2"));
    }

    /**
     * @param carrier builds the record around the given list and returns its list accessor
     * @param first   an element to put in the list
     * @param second  a different element, used to mutate the caller's list afterwards
     */
    private static <T> void assertListContract(Function<List<T>, Supplier<List<T>>> carrier, T first, T second) {
        // The caller keeps mutating its own list: the record must not see it.
        List<T> source = new ArrayList<>(List.of(first));
        Supplier<List<T>> accessor = carrier.apply(source);
        source.add(second);
        assertThat(accessor.get()).containsExactly(first);

        // The accessor never hands out a list the caller could change.
        assertThatThrownBy(() -> accessor.get().add(second)).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> accessor.get().clear()).isInstanceOf(UnsupportedOperationException.class);

        // null stays null, and null elements are tolerated (List.copyOf would throw NPE on both).
        assertThat(carrier.apply(null).get()).isNull();
        assertThat(carrier.apply(Arrays.asList(first, null)).get()).containsExactly(first, null);
    }

    private static OwncastAccessDto.Access access(String id) {
        return new OwncastAccessDto.Access(id, "default", "alice", "broadcast", "active", "admin",
                null, Instant.EPOCH, null, null);
    }

    private static OwncastModerationDto.StreamRow streamRow(String ownerSubject) {
        return new OwncastModerationDto.StreamRow(ownerSubject, "default", "title", "public", false);
    }
}
