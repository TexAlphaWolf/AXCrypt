//! Codec binario delle strutture del formato, senza serde/bincode.
//!
//! Regole comuni: interi little-endian, array a taglia fissa scritti grezzi,
//! sequenze e stringhe precedute dalla loro lunghezza.
//!
//! - **v4**: lunghezze a `u32` (indice più compatto).
//! - **v3**: lunghezze a `u64`. È esattamente il layout che produceva
//!   `bincode` 1.x con la configurazione di default, quindi gli archivi v3
//!   restano leggibili senza la dipendenza.
//!
//! Il decoder è difensivo: ogni lettura è controllata sui limiti, una
//! lunghezza dichiarata non può superare i byte rimasti (niente allocazioni
//! enormi da input malformati) e i byte in eccesso sono un errore.

use crate::error::{AxError, Result};

/// Larghezza del prefisso di lunghezza per sequenze e stringhe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LenWidth {
    U32,
    U64,
}

/// Scrittore in un buffer di memoria.
pub struct Enc {
    buf: Vec<u8>,
    lw: LenWidth,
}

impl Enc {
    pub fn new(lw: LenWidth) -> Self {
        Enc {
            buf: Vec::new(),
            lw,
        }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    /// Byte grezzi senza prefisso (array a taglia fissa).
    pub fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Prefisso di lunghezza secondo la larghezza scelta.
    pub fn len(&mut self, n: usize) -> Result<()> {
        match self.lw {
            LenWidth::U32 => {
                let v = u32::try_from(n)
                    .map_err(|_| AxError::FormatLimit("sequenza oltre 4 miliardi di elementi"))?;
                self.u32(v);
            }
            LenWidth::U64 => self.u64(n as u64),
        }
        Ok(())
    }

    pub fn str(&mut self, s: &str) -> Result<()> {
        self.len(s.len())?;
        self.raw(s.as_bytes());
        Ok(())
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Lettore su una slice, con controllo dei limiti.
pub struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
    lw: LenWidth,
}

impl<'a> Dec<'a> {
    pub fn new(buf: &'a [u8], lw: LenWidth) -> Self {
        Dec { buf, pos: 0, lw }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(AxError::Decode("dati troncati"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    /// Legge una lunghezza e verifica che `len * min_elem` byte possano
    /// ancora esistere nel buffer: un input malformato non può far allocare
    /// più memoria della dimensione dell'input stesso.
    pub fn len(&mut self, min_elem: usize) -> Result<usize> {
        let n = match self.lw {
            LenWidth::U32 => self.u32()? as u64,
            LenWidth::U64 => self.u64()?,
        };
        let n = usize::try_from(n).map_err(|_| AxError::Decode("lunghezza fuori limite"))?;
        if n.saturating_mul(min_elem.max(1)) > self.remaining() {
            return Err(AxError::Decode("lunghezza fuori limite"));
        }
        Ok(n)
    }

    pub fn string(&mut self) -> Result<String> {
        let n = self.len(1)?;
        let b = self.take(n)?;
        String::from_utf8(b.to_vec()).map_err(|_| AxError::Decode("testo non UTF-8"))
    }

    pub fn u64_vec(&mut self) -> Result<Vec<u64>> {
        let n = self.len(8)?;
        (0..n).map(|_| self.u64()).collect()
    }

    /// Fine della struttura: nessun byte deve avanzare.
    pub fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(AxError::Decode("byte in eccesso"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_entrambe_le_larghezze() {
        for lw in [LenWidth::U32, LenWidth::U64] {
            let mut e = Enc::new(lw);
            e.u8(7);
            e.u16(0xBEEF);
            e.u32(123_456);
            e.u64(u64::MAX);
            e.i64(-42);
            e.raw(&[1, 2, 3]);
            e.str("perché €").unwrap();
            e.len(2).unwrap();
            e.u64(10);
            e.u64(20);
            let b = e.finish();

            let mut d = Dec::new(&b, lw);
            assert_eq!(d.u8().unwrap(), 7);
            assert_eq!(d.u16().unwrap(), 0xBEEF);
            assert_eq!(d.u32().unwrap(), 123_456);
            assert_eq!(d.u64().unwrap(), u64::MAX);
            assert_eq!(d.i64().unwrap(), -42);
            assert_eq!(d.array::<3>().unwrap(), [1, 2, 3]);
            assert_eq!(d.string().unwrap(), "perché €");
            assert_eq!(d.u64_vec().unwrap(), vec![10, 20]);
            d.finish().unwrap();
        }
    }

    #[test]
    fn lunghezza_enorme_rifiutata_senza_allocare() {
        let mut b = u64::MAX.to_le_bytes().to_vec();
        b.extend_from_slice(&[0; 16]);
        let mut d = Dec::new(&b, LenWidth::U64);
        assert!(matches!(d.u64_vec(), Err(AxError::Decode(_))));

        let b = u32::MAX.to_le_bytes();
        let mut d = Dec::new(&b, LenWidth::U32);
        assert!(matches!(d.string(), Err(AxError::Decode(_))));
    }

    #[test]
    fn troncati_eccesso_e_utf8() {
        let mut d = Dec::new(&[1, 2], LenWidth::U32);
        assert!(d.u32().is_err());

        let d = Dec::new(&[0], LenWidth::U32);
        assert!(d.finish().is_err());

        let mut b = 2u32.to_le_bytes().to_vec();
        b.extend_from_slice(&[0xFF, 0xFE]);
        let mut d = Dec::new(&b, LenWidth::U32);
        assert!(matches!(d.string(), Err(AxError::Decode(_))));
    }
}
