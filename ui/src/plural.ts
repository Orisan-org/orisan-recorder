/**
 * "1 checkpoints" is a small thing that costs more than it looks.
 *
 * This screen exists to be believed by someone who is professionally suspicious.
 * Output that cannot count is output that has not been read by its author, and a
 * reader who notices will start wondering what else was not read.
 */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
