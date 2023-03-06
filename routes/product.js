const { verifyTokenAndAdmin } = require("../middleware/verifyToken");
const Product = require("../models/Product");

const router = require("express").Router();

//CREATE PRODUCTS
router.post("/", verifyTokenAndAdmin, (req, res) => {
  return Product.create(req.body)
    .then((product) => {
      res.status(201).json(product);
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

// UPDATE PRODUCT
router.put("/:id", verifyTokenAndAdmin, (req, res) => {
  return Product.findByIdAndUpdate(
    req.params.id,
    {
      $set: req.body,
    },
    { new: true }
  )
    .then(() => {
      res.status(200).json("Product Updated Successfuly");
    })
    .catch((err) => {
      res.status(500).json("Product Updated Failed");
    });
});

//DELETE PRODUCT
router.delete("/:id", verifyTokenAndAdmin, (req, res) => {
  return Product.findByIdAndDelete(req.params.id)
    .then(() => {
      res.status(200).json("Product Deleted Successfuly");
    })
    .catch((err) => {
      res.status(500).json("Product Deleted Failed");
    });
});

// GET PRODUCT
router.get("/find/:id", (req, res) => {
  return Product.findById(req.params.id)
    .then((product) => {
      res.status(200).json(product);
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

// GET ALL PRODUCTS
router.get("/", (req, res) => {
  const qNew = req.query.new;
  const qCategory = req.query.category;
  if (qNew) {
    return Product.find()
      .sort({ createdAt: -1 })
      .limit(1)
      .then((product) => {
        res.status(200).json(product);
      })
      .catch((err) => {
        res.status(500).json(err);
      });
  } else if (qCategory) {
    return Product.find({
      categories: {
        $in: [qCategory],
      },
    })
      .then((product) => {
        res.status(200).json(product);
      })
      .catch((err) => {
        res.status(500).json(err);
      });
  } else {
    products = Product.find()
      .then((product) => {
        res.status(200).json(product);
      })
      .catch((err) => {
        res.status(500).json(err);
      });
  }
});

module.exports = router;
