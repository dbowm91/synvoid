# Web Phase 4 & 5 Requirements

## Web Phase 4: Enhanced Directory Listing Features

### Overview
Add user-facing enhancements to the directory listing functionality for better usability in large directories.

### Requirements

#### 4.1 Sorting Options
**Problem**: Current sorting is hardcoded (dirs first, then alphabetical).

**Solution**: Add query parameter-based sorting:
- `?sort=name` (default: dirs first, then alphabetical)
- `?sort=date` (newest first for files)
- `?sort=size` (largest first)
- `?order=asc` or `?order=desc` (ascending/descending)

**Implementation**:
- Modify `render_directory_listing()` to accept sort parameters
- Update `collect_directory_entries()` to return sortable entries
- Parse `sort` and `order` query params from URL
- Apply sorting before rendering

#### 4.2 Pagination
**Problem**: Large directories render all entries, which can be slow and overwhelming.

**Solution**: Add pagination with configurable page size:
- Default page size: 100 entries
- Add navigation: First, Prev, Next, Last
- Show: "Showing X-Y of Z entries"
- Query params: `?page=1&limit=100`

**Implementation**:
- Add pagination to `DirectoryListingTemplate`
- Add page navigation controls to HTML
- Support `page` and `limit` query parameters

#### 4.3 File Type Filtering
**Problem**: No way to filter by file extension.

**Solution**: Add filter query parameter:
- `?filter=.txt` - show only .txt files
- `?filter=.txt,.md` - show .txt or .md files

**Implementation**:
- Parse `filter` query param
- Filter entries before rendering

### Acceptance Criteria
- [ ] `?sort=date` shows newest files first
- [ ] `?sort=size` shows largest files first
- [ ] `?order=asc` reverses sort direction
- [ ] `?page=2&limit=50` shows second page of 50 items
- [ ] Page navigation links work correctly
- [ ] `?filter=.txt` shows only text files

---

## Web Phase 5: Theme System Alignment

### Overview
Move directory listing CSS into the unified ThemeRenderer for consistent styling across all themeable pages.

### Requirements

#### 5.1 Consolidate Directory Listing CSS
**Problem**: `dir_listing.rs` has hardcoded `dir_css` string (lines 94-169) that duplicates theme variables.

**Solution**: Move directory listing styles into `ThemeRenderer::generate_css()`.

**Implementation**:
- Add `generate_directory_listing_css()` method to `ThemeRenderer`
- Replace hardcoded `dir_css` with call to `renderer.generate_directory_listing_css()`
- Ensure all directory listing classes use CSS variables consistently

#### 5.2 Breadcrumb Navigation
**Problem**: Only parent link (`..`) is shown, not full path breadcrumbs.

**Solution**: Add full path breadcrumb display.

**Implementation**:
- Parse URL path into segments
- Render breadcrumbs: Home > path > to > current
- Style consistently with theme

### Acceptance Criteria
- [ ] Directory listing CSS comes from `ThemeRenderer`
- [ ] All colors/spacing use CSS variables from theme config
- [ ] Breadcrumb navigation shows full path
- [ ] Custom templates respect theme variables

---

## File Changes

### Web Phase 4
- `src/static_files/directory.rs` - Add sort/pagination/filter params
- `src/theme/dir_listing.rs` - Add pagination UI, breadcrumb support

### Web Phase 5
- `src/theme/renderer.rs` - Add `generate_directory_listing_css()` method
- `src/theme/dir_listing.rs` - Use new method, add breadcrumbs

---

## Testing

1. Create directory with 150+ files
2. Test sorting options via query params
3. Test pagination navigation
4. Test file filtering
5. Verify theme changes affect directory listing consistently
6. Verify custom templates still work
