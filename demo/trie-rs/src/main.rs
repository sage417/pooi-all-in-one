use std::vec;

fn main() {
    println!("Hello, world!");
}

pub struct DoubleArrayTrie {
    base: Vec<isize>,
    check: Vec<isize>,
    size: usize,
}

impl DoubleArrayTrie {
    pub fn new() -> Self {
        let mut trie = DoubleArrayTrie {
            base: vec![0; 1024],
            check: vec![-1; 1024],
            size: 0,
        };
        trie.base[1] = 1;
        trie.check[0] = -1;
        trie
    }

    fn expand(&mut self, needed_pos: usize) {
        if needed_pos >= self.base.len() {
            let new_size = std::cmp::max(needed_pos + 1, self.base.len() * 2);
            self.base.resize(new_size, 0);
            self.check.resize(new_size, -1);
        }
    }

    fn char_to_code(&self, c: char) -> isize {
        c as u8 as isize - 'a' as u8 as isize + 1
    }

    fn set_terminal(&mut self, pos: usize) {
        let base_offset = self.base[pos];
        if base_offset == 0 {
            self.base[pos] = -1
        } else if base_offset > 0 {
            self.base[pos] = -base_offset
        }
    }

    fn is_terminal(&self, pos: usize) -> bool {
        if pos >= self.base.len() {
            return false;
        }
        self.base[pos] < 0
    }

    fn find_available_base(&mut self, children: &[isize]) -> isize {
        let mut base = 1;
        loop {
            let mut avliable = true;

            for &c in children {
                let pos = (base + c) as usize;
                if pos >= self.base.len() {
                    // need expand later
                    continue;
                }

                if self.check[pos] != -1 {
                    avliable = false;
                    break;
                }
            }

            if avliable {
                return base;
            }
            base += 1;
        }
    }

    pub fn insert(&mut self, word: &str) {
        if self.contains(word) {
            return;
        }

        let root_pos = 1;
        let mut pos = root_pos;

        let chars: Vec<char> = word.chars().collect();

        for (_i, &c) in chars.iter().enumerate() {
            let code = self.char_to_code(c);
            // no next state
            if self.base[pos] == 0 {
                self.base[pos] = 1
            }
            let mut next_pos = self.base[pos].abs() as usize + code as usize;
            self.expand(next_pos);

            if self.check[next_pos] == -1 {
                self.check[next_pos] = pos as isize;
            } else if self.check[next_pos] != pos as isize {
                self.resolve_collision(pos, code);

                next_pos = self.base[pos].abs() as usize + code as usize;
                self.expand(next_pos);
                self.check[next_pos] = pos as isize;
            }
            pos = next_pos
        }
        self.set_terminal(pos);
        self.size += 1;
    }

    fn resolve_collision(&mut self, pos: usize, code: isize) {
        let mut children = self.get_children(pos);
        children.push(code);

        let new_base_offset = self.find_available_base(&children);

        let old_base_offset = self.base[pos].abs();

        if self.base[pos] < 0 {
            self.base[pos] = -new_base_offset;
        } else {
            self.base[pos] = new_base_offset;
        }

        for c in children {
            if c == code {
                continue;
            }
            let old_idx = (old_base_offset + c) as usize;
            let new_idx = (new_base_offset + c) as usize;
            self.expand(new_idx);

            self.base[new_idx] = self.base[old_idx];
            self.check[new_idx] = pos as isize;

            if self.base[old_idx] != 0 {
                let child_base_offset = self.base[old_idx].abs();
                let grandchildren = self.get_children_of_offset(old_idx, child_base_offset);
                for gc_code in grandchildren {
                    let gc_idx = (child_base_offset + gc_code) as usize;
                    self.check[gc_idx] = new_idx as isize
                }
            }

            self.base[old_idx] = 0;
            self.check[old_idx] = -1;
        }
    }

    fn get_children(&self, pos: usize) -> Vec<isize> {
        self.get_children_of_offset(pos, self.base[pos].abs())
    }

    fn get_children_of_offset(&self, pos: usize, base_offset: isize) -> Vec<isize> {
        let mut children = Vec::new();
        if base_offset == 0 {
            return children;
        }

        for c in 0..27isize {
            if c == 0 {
                continue;
            }
            let child_pos = (base_offset + c) as usize;
            if child_pos < self.base.len() && self.check[child_pos] == pos as isize {
                children.push(c);
            }
        }

        return children;
    }

    pub fn contains(&self, word: &str) -> bool {
        self.get_index(word).is_some()
    }

    pub fn get_index(&self, word: &str) -> Option<usize> {
        let mut current_pos = 1;

        for c in word.chars() {
            let code = self.char_to_code(c);
            let next_pos = (self.base[current_pos].abs() + code) as usize;

            if next_pos >= self.check.len() || self.check[next_pos] != current_pos as isize {
                return None;
            }

            current_pos = next_pos;
        }

        if self.is_terminal(current_pos) {
            Some(-self.base[current_pos] as usize)
        } else {
            None
        }
    }

    pub fn count(&self) -> usize {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_array_trie() {
        let words = ["apple", "app", "banana", "band", "orange"];
        let mut dat = DoubleArrayTrie::new();

        for w in words {
            dat.insert(w);
        }
        assert_eq!(dat.count(), 5);

        assert!(dat.contains("apple"));
        assert!(dat.contains("app"));
        assert!(dat.contains("banana"));
        assert!(dat.contains("orange"));
        assert!(dat.contains("band"));

        assert!(!dat.contains("appl"));
        assert!(!dat.contains("ban"));
        assert!(!dat.contains("grape"));

        assert_eq!(dat.get_index("app"), Some(1));
        assert_eq!(dat.get_index("orange"), Some(1));

    }
}
