// JSDoc plugin: the library's JSDoc uses TypeScript type syntax (`(key: string) => void`,
// `Record<string, any>`, `import('./x.js').Y`, `{ a: string }`), which TypeScript reads and the jsdoc
// tool's Closure-style type parser (catharsis) does not. Each type expression jsdoc can't parse is
// shown as one it can, with the exact TypeScript type kept in the description, so nothing is lost.
const catharsis = require('catharsis');

const TAGS = /@(param|arg|argument|returns?|type|property|prop|typedef|callback|throws|this|template)\b/;

function parses(type) {
  try {
    catharsis.parse(type, { jsdoc: true });
    return true;
  } catch {
    return false;
  }
}

// What jsdoc can show for a type it can't parse.
function fallback(type) {
  if (/=>/.test(type) || /^\s*\(/.test(type)) return 'function';
  if (/^\s*\{/.test(type) || /^Record</.test(type)) return 'Object';
  if (/^Promise</.test(type)) return 'Promise';
  return '*';
}

// Finds `{...}` after a tag, with nested braces balanced, and rewrites it when jsdoc can't parse it.
function rewrite(comment) {
  let out = '';
  let i = 0;
  while (i < comment.length) {
    const rest = comment.slice(i);
    const tag = TAGS.exec(rest);
    if (!tag) { out += rest; break; }
    const start = i + tag.index + tag[0].length;
    out += comment.slice(i, start);
    let j = start;
    while (j < comment.length && /[ \t]/.test(comment[j])) j++;
    if (comment[j] !== '{') { i = start; continue; }
    let depth = 0;
    let k = j;
    for (; k < comment.length; k++) {
      if (comment[k] === '{') depth++;
      else if (comment[k] === '}' && --depth === 0) break;
    }
    const type = comment.slice(j + 1, k).replace(/\s*\n\s*\*\s*/g, ' ').trim();
    if (parses(type)) {
      out += comment.slice(start, k + 1);
    } else {
      // The tag's name (for @param/@property) follows the type; put the TypeScript type after it.
      const after = /^(\s+\[?[\w.$]+(?:=[^\]]*)?\]?)?/.exec(comment.slice(k + 1))[0];
      out += `${comment.slice(start, j)}{${fallback(type)}}${after} (TypeScript: \`${type.replace(/`/g, "'")}\`)`;
      k += after.length;
    }
    i = k + 1;
  }
  return out;
}

exports.handlers = {
  jsdocCommentFound(e) {
    e.comment = rewrite(e.comment);
  },
};
