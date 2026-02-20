use std::vec;

fn main() {
    println!("Hello, world!");
}

pub struct DoubleArrayTrie {
    base: Vec<isize>,
    check: Vec<isize>,
    size: usize,
    // use for build
    value: Option<Vec<isize>>,
    length: Option<Vec<usize>>,
    used: Vec<bool>,
    next_check_pos: usize,
}

struct Node {
    code: usize,
    depth: usize,
    left: usize,
    right: usize,
}

impl DoubleArrayTrie {
    pub fn new() -> Self {
        let mut trie = DoubleArrayTrie {
            base: vec![0; 1024],
            check: vec![-1; 1024],
            size: 0,

            // keys: vec![],
            value: Option::None,
            length: Option::None,
            used: vec![],
            next_check_pos: 0,
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
            self.used.resize(new_size, false);
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

    fn fetch(&self, parent: &Node, siblings: &mut Vec<Node>, keys: &Vec<String>) -> usize {
        let mut prev_cur = 0;
        let mut i = parent.left;

        while i < parent.right {
            let key = keys.get(i).unwrap();

            let key_len = match &self.length {
                Some(len_arr) => len_arr[i],
                None => key.chars().count(),
            };

            // let key_len = self.length.as_ref().map(|len_arr| len_arr[i])
            // .unwrap_or_else(|| tmp.chars().count());

            if key_len < parent.depth {
                continue;
            }

            let mut cur = 0;
            if parent.depth != key_len {
                if let Some(c) = key.chars().nth(parent.depth) {
                    cur = c as usize + 1
                }
            }

            if prev_cur > cur {
                return 0;
            }

            if cur != prev_cur || siblings.is_empty() {
                let tmp_node = Node {
                    code: cur,
                    depth: parent.depth + 1,
                    left: i,
                    right: 0,
                };

                if let Some(last_node) = siblings.last_mut() {
                    last_node.right = i;
                }
                siblings.push(tmp_node);
            }

            prev_cur = cur;
            i += 1;
        }

        if let Some(last_node) = siblings.last_mut() {
            last_node.right = parent.right;
        }

        return siblings.len();
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

    pub fn build(&mut self, keys: &Vec<String>) {
        self._build(keys, keys.len());
    }

    fn _build(&mut self, keys: &Vec<String>, key_size: usize) {
        if keys.is_empty() {
            return;
        }

        self.base[0] = 1;
        self.next_check_pos = 0;

        let root_node = Node {
            code: 0,
            depth: 0,
            left: 0,
            right: key_size,
        };

        let mut siblings = vec![];
        self.fetch(&root_node, &mut siblings, keys);
        self.build_insert(siblings, keys);

        // clean used
        self.used = Vec::new();
        return;
    }

    fn build_insert(&mut self, siblings: Vec<Node>, keys: &Vec<String>) -> usize {
        let mut begin = 0;
        let mut pos = if siblings.first().unwrap().code + 1 > self.next_check_pos {
            siblings.first().unwrap().code + 1
        } else {
            self.next_check_pos
        } - 1;
        let mut nonzero_num = 0u32;
        let mut first = true;

        self.expand(pos + 1);

        'outer: loop {
            pos += 1;
            self.expand(pos + 1);

            if self.check[pos] != 0 {
                nonzero_num += 1;
                continue;
            } else if first {
                self.next_check_pos = pos;
                first = false;
            }

            begin = pos - siblings.first().unwrap().code;

            if self.used[begin] {
                continue;
            }

            for node in &siblings {
                if self.check[begin + node.code] != 0 {
                    continue 'outer;
                }
            }

            break;
        }

        if 1.0f32 * nonzero_num as f32 / (pos - self.next_check_pos + 1) as f32 > 0.95f32 {
            self.next_check_pos = pos;
        }

        self.used[begin] = true;

        self.size = if self.size > begin + siblings.last().unwrap().code + 1 {
            self.size
        } else {
            begin + siblings.last().unwrap().code + 1
        };

        for node in &siblings {
            self.check[begin + node.code] = begin as isize;
        }

        for node in &siblings {
            let mut new_siblings = vec![];
            if self.fetch(node, &mut new_siblings, keys) == 0 {
                self.base[begin + node.code] = self
                    .value
                    .as_ref()
                    .map(|value_arr| -value_arr[node.left] - 1)
                    .unwrap_or_else(|| -(node.left as isize) - 1);
            } else {
                let h = self.build_insert(new_siblings, keys);
                self.base[begin + node.code as usize] = h as isize;
            }
        }

        begin
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

        let keys = vec![
            "apple".to_string(),
            "app".to_string(),
            "banana".to_string(),
            "band".to_string(),
            "orange".to_string(),
        ];
        dat = DoubleArrayTrie::new();
        // dat.build(&keys);
    }
}
