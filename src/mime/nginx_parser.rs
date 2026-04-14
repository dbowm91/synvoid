pub fn parse_nginx_mime_types(
    content: &str,
) -> Result<Vec<(String, Vec<String>)>, crate::mime::MimeError> {
    let content = remove_comments(content);

    let types_block = extract_types_block(&content).ok_or_else(|| {
        crate::mime::MimeError::ParseError("No 'types { ... }' block found".to_string())
    })?;

    parse_types_block(types_block)
}

fn remove_comments(content: &str) -> String {
    content
        .lines()
        .map(|line| {
            if let Some(pos) = line.find('#') {
                &line[..pos]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn extract_types_block(content: &str) -> Option<&str> {
    let start = content.find("types")?;
    let rest = &content[start + 5..];

    let brace_start = rest.find('{')?;
    let brace_content = &rest[brace_start + 1..];

    let mut depth = 1;
    let mut end_pos = 0;

    for (i, c) in brace_content.chars().enumerate() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end_pos = i;
                    break;
                }
            }
            _ => {}
        }
    }

    if depth == 0 {
        Some(&brace_content[..end_pos])
    } else {
        None
    }
}

fn parse_types_block(content: &str) -> Result<Vec<(String, Vec<String>)>, crate::mime::MimeError> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let mime_type = parts[0].to_string();

        if !mime_type.contains('/') {
            continue;
        }

        let extensions: Vec<String> = parts[1..]
            .iter()
            .map(|s| s.trim_end_matches(';').to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if !extensions.is_empty() {
            entries.push((mime_type, extensions));
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let content = r#"
            types {
                text/html  html htm shtml;
                image/jpeg jpeg jpg;
            }
        "#;

        let result = parse_nginx_mime_types(content).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "text/html");
        assert_eq!(result[0].1, vec!["html", "htm", "shtml"]);
    }

    #[test]
    fn test_with_comments() {
        let content = r#"
            # This is a comment
            types {
                text/html  html htm; # inline comment
                image/jpeg jpeg jpg;
            }
        "#;

        let result = parse_nginx_mime_types(content).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_multiline_mime() {
        let content = r#"
            types {
                application/vnd.openxmlformats-officedocument.wordprocessingml.document docx;
            }
        "#;

        let result = parse_nginx_mime_types(content).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].0.contains("openxmlformats"));
    }
}
