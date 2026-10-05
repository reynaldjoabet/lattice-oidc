# Modular arithmetic

Modular arithmetic is arithmetic where numbers wrap around after reaching a fixed value, the **modulus**. It underlies most of the cryptography Lattice relies on:

- **Elliptic curve keys** (ES256 tokens, passkeys): every coordinate is computed mod a 256-bit prime.
- **RSA** (RS256 tokens): signing computes $m^d \bmod n$.
- **Authenticator codes** (TOTP): the 6-digit code is a number reduced mod $10^6$ ([Totp.java](app/com/lattice/oidc/security/Totp.java)).

## Clock arithmetic

A clock works mod 12: 10:00 plus 4 hours is 2:00, not 14:00. Every value is replaced by its remainder after division by the modulus. This is called **modular reduction**:

$$
10 + 4 = 14 \equiv 2 \pmod{12}
$$

## Congruence

The symbol $\equiv$ means "congruent": their difference is a multiple of the modulus. Equivalently, both sides leave the same remainder from $0$ to $m - 1$ when divided by the modulus $m$. It is used instead of $=$ because the two sides usually only match after wrapping around. For example, $6^2 = 36$, and $36 \equiv 2 \pmod{17}$ because $36 - 2 = 34$ is a multiple of 17.

**Formal definition.** Let $a, r, m \in \mathbb{Z}$ with $m > 0$. We write

$$
a \equiv r \pmod{m}
$$

if $m$ divides $a - r$, written $m \mid (a - r)$. $m$ is the **modulus** and $r$ a **remainder**. In the example, $17 \mid (36 - 2)$ because $34 = 2 \times 17$.

## The remainder is not unique

Take $a = 42$ and $m = 9$. Each way of writing 42 as a multiple of 9 plus something gives a valid remainder:

| Write 42 as | Remainder $r$ | Check: $9 \mid (42 - r)$ |
| --- | --: | --- |
| $42 = 4 \cdot 9 + 6$ | $6$ | $42 - 6 = 36 = 4 \cdot 9$ ✓ |
| $42 = 3 \cdot 9 + 15$ | $15$ | $42 - 15 = 27 = 3 \cdot 9$ ✓ |
| $42 = 5 \cdot 9 + (-3)$ | $-3$ | $42 + 3 = 45 = 5 \cdot 9$ ✓ |

So $42 \equiv 6 \equiv 15 \equiv -3 \pmod{9}$. **The remainder is not unique:** any two remainders differ by a multiple of $m$.

When a single value is wanted, the convention is the one from $0$ to $m - 1$, written $42 \bmod 9 = 6$.

**In code.** Java's `%` keeps the sign of the left operand, so it can return a negative remainder: `-3 % 9` is `-3`. `Math.floorMod(-3, 9)` returns `6`, the conventional one. `Totp.java` can use `%` safely because it masks the sign bit first (`& 0x7f`), so the number is never negative.

## Equivalence classes

Take $a = 12$ and $m = 5$:

| Congruence | Check |
| --- | --- |
| $12 \equiv 2 \pmod{5}$ | $5 \mid (12 - 2) = 10$ ✓ |
| $12 \equiv 7 \pmod{5}$ | $5 \mid (12 - 7) = 5$ ✓ |
| $12 \equiv -3 \pmod{5}$ | $5 \mid (12 - (-3)) = 15$ ✓ |

**Definition.** The set

$$
\{\ldots, -8, -3, 2, 7, 12, 17, \ldots\}
$$

forms an **equivalence class** modulo 5: each member is the previous one plus 5. All members of the class behave equivalently modulo 5.

### All the classes modulo 5

Every integer falls into exactly one of five classes:

| Class | Members | Smallest non-negative member |
| :-: | --- | :-: |
| A | $\{\ldots, -10, -5, 0, 5, 10, \ldots\}$ | 0 |
| B | $\{\ldots, -9, -4, 1, 6, 11, 16, \ldots\}$ | 1 |
| C | $\{\ldots, -8, -3, 2, 7, 12, \ldots\}$ | 2 |
| D | $\{\ldots, -7, -2, 3, 8, 13, \ldots\}$ | 3 |
| E | $\{\ldots, -6, -1, 4, 9, 14, \ldots\}$ | 4 |

In general there are $m$ classes modulo $m$. Picking the smallest non-negative member of each gives the set $\mathbb{Z}_m = \{0, 1, \ldots, m - 1\}$, which is what computers work with.

## Computing with classes

Because all members of a class behave the same way, any member can stand in for its class. Compute $13 \cdot 16 - 8 \pmod{5}$. Done directly, it needs a multiplication first:

$$
13 \cdot 16 - 8 = 208 - 8 = 200 \equiv 0 \pmod{5}
$$

Instead, look up each number's class: 13 is in D, 16 in B and 8 in D. The expression becomes $D \cdot B - D$, and each class can be replaced by its smallest member (D by 3, B by 1):

$$
3 \cdot 1 - 3 = 3 - 3 = 0 \pmod{5}
$$

Same answer, class A, with numbers small enough to do in your head. The result depends only on the classes, not on which members are picked.

**Why it matters: reduce early.** The intermediate results can always be reduced, so the numbers never grow. For example, $3^8 \bmod 7$, by repeated squaring:

$$
3^2 = 9 \equiv 2 \qquad 3^4 \equiv 2^2 = 4 \qquad 3^8 \equiv 4^2 = 16 \equiv 2 \pmod{7}
$$

The direct way agrees: $3^8 = 6561 = 937 \cdot 7 + 2$. With a 3072-bit RSA modulus, $m^d$ written out in full would have more digits than there are atoms in the universe. Reducing after every squaring keeps each step at 3072 bits, which is the only reason RSA can be computed at all.

## Division and inverses

Modular arithmetic has addition, subtraction and multiplication, but no division. "Dividing by $a$" means multiplying by the **inverse** of $a$: the number $a^{-1}$ with $a \times a^{-1} \equiv 1 \pmod{m}$. Not every number has one.

**The trap of composite numbers.** Take a non-prime modulus such as 6. The numbers are 0 to 5. To find the inverse of 2, we need an $x$ with $2 \times x \equiv 1 \pmod{6}$:

| $x$ | $2 \times x$ | $\bmod 6$ |
| --: | --: | --: |
| 1 | 2 | 2 |
| 2 | 4 | 4 |
| 3 | 6 | **0** |
| 4 | 8 | 2 |
| 5 | 10 | 4 |

- **No inverse.** $2 \times x$ never equals 1, because 2 shares a factor with 6. So 2 has no inverse, and nothing can be divided by 2.
- **A zero divisor.** Worse, $2 \times 3 \equiv 0$: two non-zero numbers multiply to zero. Information is lost, because you can't tell what was multiplied by 2 to get 0.

**The prime guarantee.** Now use a prime modulus such as 7. The numbers are 0 to 6. Find the inverse of 2 again:

| $x$ | $2 \times x$ | $\bmod 7$ |
| --: | --: | --: |
| 1 | 2 | 2 |
| 2 | 4 | 4 |
| 3 | 6 | 6 |
| 4 | 8 | **1** |

The inverse of 2 is 4. This isn't luck: a prime has no divisors other than 1 and itself, so no number from 1 to $p - 1$ shares a factor with it. That guarantees:

- every non-zero number has exactly one inverse, so division always works;
- no two non-zero numbers multiply to zero, so nothing collapses.

This is why an elliptic curve's modulus is always prime: its point-addition rule divides (the slope $\frac{y_2 - y_1}{x_2 - x_1}$), so every non-zero number must have an inverse. The README's [Elliptic curve keys](README.md#elliptic-curve-keys-how-they-work) section shows the curve built on top of this.
