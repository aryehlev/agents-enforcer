use warp::{Filter, Rejection, Reply};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

pub fn static_routes(
    static_dir: String,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    // Serve index.html at root
    let index_route = warp::path::end()
        .and(serve_index(static_dir.clone()));

    // Serve static files
    let static_route = warp::path("static")
        .and(warp::fs::dir(static_dir.clone()))
        .map(|reply| {
            warp::reply::with_header(reply, "Cache-Control", "public, max-age=3600")
        });

    index_route.or(static_route)
}

fn serve_index(
    static_dir: String,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::any()
        .and_then(move || {
            let static_dir = static_dir.clone();
            async move {
                let path = PathBuf::from(&static_dir).join("index.html");
                debug!("Serving index.html from {:?}", path);

                if path.exists() {
                    match tokio::fs::read(&path).await {
                        Ok(contents) => Ok::<_, Rejection>(warp::reply::html(String::from_utf8_lossy(&contents).to_string())),
                        Err(e) => {
                            warn!("Failed to read index.html: {}", e);
                            Err(warp::reject::not_found())
                        }
                    }
                } else {
                    warn!("index.html not found at {:?}", path);
                    Err(warp::reject::not_found())
                }
            }
        })
}

// Security helper: validate path to prevent directory traversal
pub fn is_safe_path(base_dir: &Path, requested_path: &Path) -> bool {
    if let Ok(canonical) = requested_path.canonicalize() {
        if let Ok(base_canonical) = base_dir.canonicalize() {
            return canonical.starts_with(base_canonical);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_safe_path_validation() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();
        
        // Create a test file
        let safe_file = base.join("test.txt");
        fs::write(&safe_file, "test").unwrap();
        
        // Safe path
        assert!(is_safe_path(base, &safe_file));
        
        // Unsafe path (trying to escape)
        let unsafe_path = base.join("../../../etc/passwd");
        assert!(!is_safe_path(base, &unsafe_path));
    }
}
