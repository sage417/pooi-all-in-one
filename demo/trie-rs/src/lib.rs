use std::vec;

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

#[derive(Debug)]
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
            check: vec![0; 1024],
            size: 0,

            // keys: vec![],
            value: Option::None,
            length: Option::None,
            used: vec![false; 1024],
            next_check_pos: 0,
        };
        trie.base[0] = 1;
        // trie.base[1] = 1;
        // trie.check[0] = -1;
        trie
    }

    fn expand(&mut self, needed_pos: usize) {
        if needed_pos >= self.base.len() {
            let new_size = std::cmp::max(needed_pos + 1, self.base.len() * 2);
            self.base.resize(new_size, 0);
            self.check.resize(new_size, 0);
            self.used.resize(new_size, false);
        }
    }

    fn fetch(&self, parent: &Node, siblings: &mut Vec<Node>, keys: &Vec<String>) -> usize {
        let mut prev = 0;
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
                break;
            }

            let mut cur = 0;
            if parent.depth != key_len {
                if let Some(c) = key.chars().nth(parent.depth) {
                    cur = c as usize + 1 // char -> c code
                }
            }

            if prev > cur {
                // err -3 not sorted asc?
                return 0;
            }

            if cur != prev || siblings.is_empty() {
                let new_parent = Node {
                    code: cur,
                    depth: parent.depth + 1,
                    left: i,
                    right: 0,
                };

                if let Some(last_node) = siblings.last_mut() {
                    last_node.right = i; // last_node.right = new_node.left
                }
                siblings.push(new_parent);
            }

            prev = cur;
            i += 1;
        }

        if let Some(last_node) = siblings.last_mut() {
            last_node.right = parent.right;
        }

        return siblings.len();
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
        let mut pos = std::cmp::max(siblings.first().unwrap().code + 1, self.next_check_pos) - 1;
        let mut begin;
        let mut nonzero_num = 0;
        let mut first = true;

        self.expand(pos + 1);

        'find_begin: loop {
            pos += 1;
            self.expand(pos + 1);

            if self.check[pos] != 0 {
                nonzero_num += 1;
                continue;
            } else if first {
                self.next_check_pos = pos;
                first = false;
            }

            // assert_eq!(begin, pos - siblings.first().unwrap().code);
            begin = pos - siblings.first().unwrap().code;
            // ensure begin not used and check[node.code] all em
            if self.used[begin] {
                continue;
            }
            for node in &siblings[1..] {
                if self.check[begin + node.code] != 0 {
                    continue 'find_begin;
                }
            }

            break;
        }

        if 1.0f64 * nonzero_num as f64 / (pos - self.next_check_pos + 1) as f64 > 0.95f64 {
            self.next_check_pos = pos;
        }

        self.used[begin] = true;

        self.size = std::cmp::max(self.size, begin + siblings.last().unwrap().code + 1);

        for node in &siblings {
            self.check[begin + node.code] = begin as isize;
        }

        for node in &siblings {
            let mut new_siblings = vec![];

            if self.fetch(node, &mut new_siblings, keys) == 0 {
                // leaf node
                self.base[begin + node.code] = match &self.value {
                    Some(value_arr) => -value_arr[node.left] - 1,
                    None => -(node.left as isize) - 1,
                };

                if let Some(value_arr) = &self.value {
                    if -value_arr[node.left] - 1 >= 0 {
                        // err -2 wrong value?
                        return 0;
                    }
                }
            } else {
                let h = self.build_insert(new_siblings, keys);
                self.base[begin + node.code] = h as isize;
            }
        }

        begin
    }

    pub fn exact_match_v2(&self, word: &str) -> Option<usize> {
        // root pos = 0
        let mut pos = 0;
        // t = base[p] + c
        // check[p] = t - c or base[p]
        for c in word.chars() {
            let offset = self.base[pos];
            pos = offset as usize + c as usize + 1;

            if offset != self.check[pos] {
                return None
            }
        }
        // next state
        let offset = self.base[pos];
        pos = offset as usize;
        let next_offset = self.base[pos];

        // state valid and is terminal
        if offset == self.check[pos] && next_offset < 0 {
            Some((-next_offset - 1) as usize)
        } else {
            None
        }
    }

    pub fn exact_match(&self, word: &str) -> Option<usize> {
        let node_pos = 0;

        let mut base_offset = self.base[node_pos];
        let mut current_pos: usize;

        for c in word.chars() {
            current_pos = base_offset as usize + c as usize + 1;
            if base_offset == self.check[current_pos] {
                base_offset = self.base[current_pos]
            } else {
                return None;
            }
        }
        current_pos = base_offset as usize;
        let n = self.base[current_pos];

        if base_offset == self.check[current_pos] && n < 0 {
            Some((-n - 1) as usize)
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
        let mut dat = DoubleArrayTrie::new();
        let mut keys = vec![
            "app".to_string(),
            "apple".to_string(),
            "banana".to_string(),
            "band".to_string(),
            "orange".to_string(),
        ];
        keys.sort();
        dat = DoubleArrayTrie::new();
        dat.build(&keys);

        // assert_eq!(dat.size, 224);
        assert!(dat.exact_match_v2("apple").is_some());
        assert!(dat.exact_match_v2("app").is_some());
        assert!(dat.exact_match_v2("banana").is_some());
        assert!(dat.exact_match_v2("orange").is_some());
        assert!(dat.exact_match_v2("band").is_some());

        assert!(dat.exact_match_v2("appl").is_none());
        assert!(dat.exact_match_v2("ban").is_none());
        assert!(dat.exact_match_v2("grape").is_none());
    }

    #[test]
    fn test_single_key() {
        let mut dat = DoubleArrayTrie::new();
        let keys = vec!["hello".to_string()];
        dat.build(&keys);

        assert!(dat.exact_match_v2("hello").is_some());
        assert!(dat.exact_match_v2("hell").is_none());
        assert!(dat.exact_match_v2("hello1").is_none());
    }

    #[test]
    fn test_single_char() {
        let mut dat = DoubleArrayTrie::new();
        let mut keys = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        keys.sort();
        dat.build(&keys);

        assert!(dat.exact_match_v2("a").is_some());
        assert!(dat.exact_match_v2("b").is_some());
        assert!(dat.exact_match_v2("c").is_some());
        assert!(dat.exact_match_v2("d").is_some());
        assert!(dat.exact_match_v2("e").is_none());
    }

    #[test]
    fn test_prefix_keys() {
        let mut dat = DoubleArrayTrie::new();
        let mut keys = vec![
            "a".to_string(),
            "ab".to_string(),
            "abc".to_string(),
            "abcd".to_string(),
        ];
        keys.sort();
        dat.build(&keys);

        assert!(dat.exact_match_v2("a").is_some());
        assert!(dat.exact_match_v2("ab").is_some());
        assert!(dat.exact_match_v2("abc").is_some());
        assert!(dat.exact_match_v2("abcd").is_some());

        assert!(dat.exact_match_v2("").is_none());
        assert!(dat.exact_match_v2("abcde").is_none());
    }

    #[test]
    fn test_no_common_prefix() {
        let mut dat = DoubleArrayTrie::new();
        let mut keys = vec![
            "cat".to_string(),
            "dog".to_string(),
            "fish".to_string(),
            "bird".to_string(),
        ];
        keys.sort();
        dat.build(&keys);

        assert!(dat.exact_match_v2("cat").is_some());
        assert!(dat.exact_match_v2("dog").is_some());
        assert!(dat.exact_match_v2("fish").is_some());
        assert!(dat.exact_match_v2("bird").is_some());

        assert!(dat.exact_match_v2("ca").is_none());
        assert!(dat.exact_match_v2("do").is_none());
    }

    #[test]
    fn test_non_exist() {
        let mut dat = DoubleArrayTrie::new();
        let mut keys = vec!["hello".to_string(), "world".to_string()];
        keys.sort();
        dat.build(&keys);

        assert!(dat.exact_match_v2("hello").is_some());
        assert!(dat.exact_match_v2("world").is_some());

        assert!(dat.exact_match_v2("hell").is_none());
        assert!(dat.exact_match_v2("wor").is_none());

        assert!(dat.exact_match_v2("helloworld").is_none());
        assert!(dat.exact_match_v2("world123").is_none());

        assert!(dat.exact_match_v2("test").is_none());
    }
}
