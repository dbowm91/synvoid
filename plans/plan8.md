# Edge Node Caching and Image Poisoning Improvement Plan

## Objective
Refine the edge node caching and image poisoning architecture. In mesh mode, the origin node must forward its transformation preferences to the edge node, which is responsible for applying these transformations and caching the result. The origin node should act purely as a backend. In non-mesh mode, where the origin acts as its own edge node, it should apply the configured preferences correctly.

## Background & Motivation
The current implementation suffers from architectural ambiguity. In mesh mode, the origin node incorrectly applies some transformations (like minification) itself instead of relying on the edge node. Furthermore, in non-mesh (standalone) mode, the origin node falls back to default image poisoning settings instead of using the site-specific configuration. This plan outlines the necessary adjustments to enforce a clear separation of concerns in mesh mode and correct configuration application in standalone mode.

## Proposed Strategy: DHT-Based Preference Sync
The edge node will continue to use the Distributed Hash Table (DHT) to fetch the origin's transformation preferences (image poisoning, minification, compression, image protection). The origin node will be updated to publish these settings but will stop applying them to outbound mesh traffic.

## Implementation Steps

### Phase 1: Origin Node Rectification (Mesh Mode)
1.  **Remove Origin-Side Transformations**:
    *   **File**: `src/mesh/transport_peer.rs`
    *   **Action**: Remove the `apply_response_transforms` method. The origin node must not perform minification, compression, or image poisoning on responses destined for an edge node.
    *   **Action**: Simplify `handle_http_proxy_stream` to send the raw `full_response` back to the edge node directly.

### Phase 2: Standalone Mode Configuration Fix
1.  **Enforce Site Configuration for Image Poisoning**:
    *   **File**: `src/http/server.rs`
    *   **Action**: Modify the signature of `apply_image_poisoning` to accept an optional reference to `SiteImagePoisonConfig`.
    *   **Action**: Inside `apply_image_poisoning`, pass the configuration fields (`level`, `intensity`, `seed`, `max_dimension`, `jpeg_quality`) to the `PoisonImageClient` instead of hardcoding `None`.
    *   **Action**: Update all call sites of `apply_image_poisoning` within `handle_request` to pass the appropriate `SiteImagePoisonConfig`. This requires fetching the configuration from the DHT via `MeshTransportManager` in mesh mode and from `site_config` in standalone mode.

### Phase 3: Edge Node Verification
1.  **Confirm Edge Node Behavior**:
    *   **File**: `src/mesh/proxy.rs`
    *   **Action**: Verify that `transform_response` correctly retrieves preferences (`get_image_protection_for_site`, `get_image_poison_config_for_site`, `get_minification_for_site`) from the `transport_manager`.
    *   **Action**: Verify that the edge node applies these transforms to the raw backend response and correctly caches the result using the DHT transform cache (`record_store`).

## Verification
*   **Mesh Mode Validation**: Deploy an origin node and an edge node. Confirm that transformations (minification, image poisoning) are executed *only* by the edge node, not the origin, and that the edge node caches the result in the DHT.
*   **Standalone Validation**: Deploy a single node. Confirm that image poisoning utilizes the `level` and `intensity` defined in the site configuration, verifying that default settings are no longer used when a configuration is present.
