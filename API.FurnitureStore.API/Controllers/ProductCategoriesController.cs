using API.FurnitureStore.Data;
using Microsoft.AspNetCore.Mvc;
using API.FurnitureStore.Shared;
using Microsoft.EntityFrameworkCore;

namespace API.FurnitureStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductCategoriesController : ControllerBase
    {
        private readonly APIFurnitureContext _context;

        public ProductCategoriesController(APIFurnitureContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<IEnumerable<ProductCategory>> GetProductCategories()
        {
            return await _context.ProductCategories.ToListAsync();
        }

        [HttpGet("id")]
        public async Task<IActionResult> GetProductCategory(int id)
        {
            ProductCategory? productCategory = await _context.ProductCategories.FirstOrDefaultAsync(pc => pc.Id == id);
            if (productCategory == null)
                return NotFound();

            return Ok(productCategory);
        }

        [HttpPost]
        public async Task<IActionResult> CreateProductCategory(ProductCategory productCategory)
        {
            await _context.ProductCategories.AddAsync(productCategory);
            await _context.SaveChangesAsync();

            return CreatedAtAction("CreateProductCategory", productCategory.Id, productCategory);
        }

        [HttpPut]
        public async Task<IActionResult> UpdateProductCategory(ProductCategory productCategory)
        {
            _context.ProductCategories.Update(productCategory);
            await _context.SaveChangesAsync();
            return NoContent();
        }

        [HttpDelete("id")]
        public async Task<IActionResult> DeleteProductCategory(int id)
        {
            ProductCategory? productCategory = await _context.ProductCategories.FindAsync(id);
            if (productCategory == null)
                return NotFound();

            _context.ProductCategories.Remove(productCategory);
            await _context.SaveChangesAsync();
            return NoContent();
        }
    }
}
