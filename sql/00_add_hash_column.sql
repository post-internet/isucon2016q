ALTER TABLE entry ADD keyword_hash CHAR(40);
UPDATE entry SET keyword_hash = SHA1(keyword);
