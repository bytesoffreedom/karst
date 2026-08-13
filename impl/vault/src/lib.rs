//! The container's storage layer.
//!
//! Two spaces (public and hidden) live in one file of fixed size, and which of them exists is not
//! something the file can be made to say. The design this implements is `duress_container_plan`,
//! kept outside the repository; what matters here is that the geometry is a constant of the format
//! and every mutation reserves its worst case before it changes a byte.
//!
//! Built bottom-up and in this order, because each layer's tests are meaningless without the one
//! below it: geometry, then the credit planner, then records, blocks, the ownership layer, the
//! allocator, the map, and only then transactions.

pub mod geometry;
pub mod plan;
pub mod record;
pub mod allocator;
pub mod map;
pub mod capsule;
pub mod freeindex;
pub mod slot;
pub mod root;
pub mod faulty;
