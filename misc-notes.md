# Miscellaneous notes

Notes that don't belong in the README.

## Fonts

## Why I'd still self-host rather than use the CDN:

| | Self-hosted (now) | Google Fonts CDN |
| --- | --- | --- |
| Privacy | No third party sees your users | Every visit to your sign-in page sends the user's IP to Google. A German court ruled this a GDPR violation in 2022. |


## Scala 3 explicit nulls and `Option`

```scala
def apply[A](x: A | Null): Option[A] = if (x == null) None else Some(x)

final def orNull[A1 >: A | Null]: A1 = this.getOrElse(null)
```

Because the parameter is `A | Null`, passing a `String | Null` infers `A = String`:

```scala
//> using options -Yexplicit-nulls   (3.9.0)
val s: String | Null = System.getProperty("user.home")

val o: Option[String] = Option(s)   // ok
o.map(_.length)                     // ok, no .nn

val back = o.orNull                 // String | Null, no implicit evidence needed
```
